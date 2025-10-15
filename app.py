#!/usr/bin/env python3
"""
MITRE ATT&CK Intelligence Framework
Advanced threat intelligence aggregation and analysis tool

Author: Marcos Tolosa
License: MIT
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from functools import lru_cache
import hashlib

import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.logging import RichHandler
from rich.prompt import Confirm
import typer
from pydantic import BaseModel, Field, validator
from diskcache import Cache

# ============================================================================
# CONFIGURAÇÃO E LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)
logger = logging.getLogger("mitre_attck")

console = Console()

# ============================================================================
# MODELS E ENUMS
# ============================================================================

class TacticPhase(str, Enum):
    """MITRE ATT&CK Tactic Phases"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class Platform(str, Enum):
    """Supported platforms"""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    CLOUD = "Cloud"
    CONTAINERS = "Containers"
    NETWORK = "Network"
    ANDROID = "Android"
    IOS = "iOS"


class RiskLevel(str, Enum):
    """Risk assessment levels (baseado em contexto operacional)"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ExternalReference:
    """External reference metadata"""
    source_name: str
    external_id: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None


@dataclass
class KillChainPhase:
    """Kill chain phase information"""
    kill_chain_name: str
    phase_name: str


@dataclass
class Technique:
    """MITRE ATT&CK Technique representation"""
    id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    defense_bypassed: List[str] = field(default_factory=list)
    detection: Optional[str] = None
    external_references: List[ExternalReference] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_technique: Optional[str] = None
    deprecated: bool = False
    revoked: bool = False
    
    @property
    def mitre_id(self) -> str:
        """Extract MITRE ATT&CK ID"""
        for ref in self.external_references:
            if ref.source_name == "mitre-attack":
                return ref.external_id or "N/A"
        return "N/A"
    
    @property
    def mitre_url(self) -> Optional[str]:
        """Get MITRE ATT&CK URL"""
        for ref in self.external_references:
            if ref.source_name == "mitre-attack":
                return ref.url
        return None
    
    def calculate_risk_score(self) -> tuple[RiskLevel, int]:
        """
        Calcula score de risco baseado em fatores operacionais reais
        
        Critérios:
        - Múltiplas plataformas = maior superfície de ataque
        - Baixa permissão necessária = mais fácil exploração
        - Bypass de defesas = evasão avançada
        - Subtécnicas = variações complexas
        """
        score = 0
        
        # Multi-platform (maior impacto)
        if len(self.platforms) >= 4:
            score += 3
        elif len(self.platforms) >= 2:
            score += 2
            
        # Baixo requisito de permissão (mais perigoso)
        low_perms = {"User", "user", ""}
        if any(perm in low_perms for perm in self.permissions_required) or not self.permissions_required:
            score += 2
            
        # Defense bypass capabilities
        if self.defense_bypassed:
            score += len(self.defense_bypassed)
            
        # Subtécnica indica sofisticação
        if self.is_subtechnique:
            score += 1
            
        # Deprecated/revoked são menos relevantes
        if self.deprecated or self.revoked:
            score -= 3
        
        # Classificação
        if score >= 7:
            return RiskLevel.CRITICAL, score
        elif score >= 5:
            return RiskLevel.HIGH, score
        elif score >= 3:
            return RiskLevel.MEDIUM, score
        elif score >= 0:
            return RiskLevel.LOW, score
        else:
            return RiskLevel.INFO, score


# ============================================================================
# CACHE LAYER
# ============================================================================

class CacheManager:
    """Advanced caching with TTL and invalidation"""
    
    def __init__(self, cache_dir: Path, ttl_hours: int = 24):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache = Cache(str(self.cache_dir))
        self.ttl = ttl_hours * 3600  # Convert to seconds
        logger.debug(f"Cache initialized at {cache_dir} with TTL={ttl_hours}h")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve from cache if not expired"""
        try:
            return self.cache.get(key)
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
            return None
    
    def set(self, key: str, value: Any) -> None:
        """Store in cache with TTL"""
        try:
            self.cache.set(key, value, expire=self.ttl)
        except Exception as e:
            logger.error(f"Cache write error: {e}")
    
    def invalidate(self, pattern: Optional[str] = None) -> None:
        """Invalidate cache entries"""
        if pattern:
            # Implement pattern matching if needed
            pass
        else:
            self.cache.clear()
            logger.info("Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Cache statistics"""
        return {
            "size": len(self.cache),
            "volume": self.cache.volume(),
        }


# ============================================================================
# DATA FETCHER
# ============================================================================

class MitreAttackFetcher:
    """Async MITRE ATT&CK data fetcher with retry logic"""
    
    BASE_URL = "https://raw.githubusercontent.com/mitre/cti"
    DEFAULT_BRANCH = "master"
    
    def __init__(
        self,
        cache_manager: CacheManager,
        timeout: int = 30,
        max_retries: int = 3
    ):
        self.cache = cache_manager
        self.timeout = timeout
        self.max_retries = max_retries
        
    async def fetch_enterprise_attack(self, version: str = "master") -> Optional[Dict[str, Any]]:
        """Fetch MITRE ATT&CK Enterprise dataset"""
        cache_key = f"mitre_enterprise_{version}"
        
        # Try cache first
        cached_data = self.cache.get(cache_key)
        if cached_data:
            logger.debug("Using cached ATT&CK data")
            return cached_data
        
        # Fetch from GitHub
        url = f"{self.BASE_URL}/{version}/enterprise-attack/enterprise-attack.json"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for attempt in range(1, self.max_retries + 1):
                try:
                    logger.info(f"Fetching ATT&CK data (attempt {attempt}/{self.max_retries})...")
                    response = await client.get(url)
                    response.raise_for_status()
                    
                    data = response.json()
                    self.cache.set(cache_key, data)
                    logger.info(f"✓ Fetched {len(data.get('objects', []))} objects")
                    return data
                    
                except httpx.HTTPStatusError as e:
                    logger.error(f"HTTP {e.response.status_code}: {e}")
                    if attempt == self.max_retries:
                        return None
                        
                except Exception as e:
                    logger.error(f"Fetch error: {e}")
                    if attempt < self.max_retries:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        return None
        
        return None


# ============================================================================
# PARSER E FILTROS
# ============================================================================

class TechniqueParser:
    """Parse and filter MITRE ATT&CK techniques"""
    
    @staticmethod
    def parse_technique(obj: Dict[str, Any]) -> Optional[Technique]:
        """Parse raw JSON object to Technique dataclass"""
        if obj.get("type") != "attack-pattern":
            return None
        
        # External references
        ext_refs = []
        for ref in obj.get("external_references", []):
            ext_refs.append(ExternalReference(
                source_name=ref.get("source_name", ""),
                external_id=ref.get("external_id"),
                url=ref.get("url"),
                description=ref.get("description")
            ))
        
        # Kill chain phases (tactics)
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))
        
        # Check if subtechnique
        name = obj.get("name", "")
        is_sub = "." in obj.get("x_mitre_shortname", "")
        parent = None
        if is_sub:
            # Extract parent from external ID
            for ref in ext_refs:
                if ref.source_name == "mitre-attack" and ref.external_id:
                    if "." in ref.external_id:
                        parent = ref.external_id.split(".")[0]
        
        return Technique(
            id=obj.get("id", ""),
            name=name,
            description=obj.get("description", ""),
            tactics=tactics,
            platforms=obj.get("x_mitre_platforms", []),
            permissions_required=obj.get("x_mitre_permissions_required", []),
            data_sources=obj.get("x_mitre_data_sources", []),
            defense_bypassed=obj.get("x_mitre_defense_bypassed", []),
            detection=obj.get("x_mitre_detection"),
            external_references=ext_refs,
            is_subtechnique=is_sub,
            parent_technique=parent,
            deprecated=obj.get("x_mitre_deprecated", False),
            revoked=obj.get("revoked", False)
        )
    
    @staticmethod
    def filter_techniques(
        techniques: List[Technique],
        keyword: Optional[str] = None,
        tactics: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None,
        min_risk: Optional[RiskLevel] = None,
        exclude_deprecated: bool = True,
        exclude_revoked: bool = True,
    ) -> List[Technique]:
        """Apply comprehensive filters"""
        filtered = techniques
        
        # Exclude deprecated/revoked
        if exclude_deprecated:
            filtered = [t for t in filtered if not t.deprecated]
        if exclude_revoked:
            filtered = [t for t in filtered if not t.revoked]
        
        # Keyword search (case-insensitive, multi-field)
        if keyword:
            kw_lower = keyword.lower()
            filtered = [
                t for t in filtered
                if kw_lower in t.name.lower()
                or kw_lower in t.description.lower()
                or kw_lower in t.mitre_id.lower()
            ]
        
        # Tactic filter
        if tactics:
            filtered = [
                t for t in filtered
                if any(tactic in t.tactics for tactic in tactics)
            ]
        
        # Platform filter
        if platforms:
            filtered = [
                t for t in filtered
                if any(platform in t.platforms for platform in platforms)
            ]
        
        # Risk level filter
        if min_risk:
            risk_order = {
                RiskLevel.INFO: 0,
                RiskLevel.LOW: 1,
                RiskLevel.MEDIUM: 2,
                RiskLevel.HIGH: 3,
                RiskLevel.CRITICAL: 4
            }
            min_level = risk_order[min_risk]
            filtered = [
                t for t in filtered
                if risk_order[t.calculate_risk_score()[0]] >= min_level
            ]
        
        return filtered


# ============================================================================
# EXPORT HANDLERS
# ============================================================================

class ExportHandler:
    """Handle various export formats"""
    
    @staticmethod
    def to_csv(techniques: List[Technique], filepath: Path) -> None:
        """Export to CSV"""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'MITRE_ID', 'Name', 'Tactics', 'Platforms', 'Risk_Level',
                'Risk_Score', 'Permissions', 'Defense_Bypassed', 'Detection',
                'Description', 'URL'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for tech in techniques:
                risk_level, risk_score = tech.calculate_risk_score()
                writer.writerow({
                    'MITRE_ID': tech.mitre_id,
                    'Name': tech.name,
                    'Tactics': ', '.join(tech.tactics),
                    'Platforms': ', '.join(tech.platforms),
                    'Risk_Level': risk_level.value,
                    'Risk_Score': risk_score,
                    'Permissions': ', '.join(tech.permissions_required),
                    'Defense_Bypassed': ', '.join(tech.defense_bypassed),
                    'Detection': tech.detection or 'N/A',
                    'Description': tech.description[:200],
                    'URL': tech.mitre_url or 'N/A'
                })
        
        console.print(f"[green]✓ Exported {len(techniques)} techniques to {filepath}[/green]")
    
    @staticmethod
    def to_json(techniques: List[Technique], filepath: Path, pretty: bool = True) -> None:
        """Export to JSON"""
        data = []
        for tech in techniques:
            risk_level, risk_score = tech.calculate_risk_score()
            tech_dict = {
                'mitre_id': tech.mitre_id,
                'name': tech.name,
                'description': tech.description,
                'tactics': tech.tactics,
                'platforms': tech.platforms,
                'risk_level': risk_level.value,
                'risk_score': risk_score,
                'permissions_required': tech.permissions_required,
                'defense_bypassed': tech.defense_bypassed,
                'detection': tech.detection,
                'url': tech.mitre_url,
                'is_subtechnique': tech.is_subtechnique,
                'parent': tech.parent_technique
            }
            data.append(tech_dict)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)
        
        console.print(f"[green]✓ Exported {len(techniques)} techniques to {filepath}[/green]")
    
    @staticmethod
    def to_markdown(techniques: List[Technique], filepath: Path) -> None:
        """Export to Markdown report"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# MITRE ATT&CK Technique Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Techniques:** {len(techniques)}\n\n")
            f.write("---\n\n")
            
            for tech in techniques:
                risk_level, risk_score = tech.calculate_risk_score()
                f.write(f"## {tech.mitre_id}: {tech.name}\n\n")
                f.write(f"**Risk Level:** {risk_level.value} (Score: {risk_score})\n\n")
                f.write(f"**Tactics:** {', '.join(tech.tactics)}\n\n")
                f.write(f"**Platforms:** {', '.join(tech.platforms)}\n\n")
                
                if tech.permissions_required:
                    f.write(f"**Permissions Required:** {', '.join(tech.permissions_required)}\n\n")
                
                if tech.defense_bypassed:
                    f.write(f"**Defense Bypassed:** {', '.join(tech.defense_bypassed)}\n\n")
                
                f.write(f"**Description:**\n{tech.description}\n\n")
                
                if tech.detection:
                    f.write(f"**Detection:**\n{tech.detection}\n\n")
                
                if tech.mitre_url:
                    f.write(f"**Reference:** [{tech.mitre_url}]({tech.mitre_url})\n\n")
                
                f.write("---\n\n")
        
        console.print(f"[green]✓ Exported markdown report to {filepath}[/green]")


# ============================================================================
# DISPLAY
# ============================================================================

class DisplayHandler:
    """Rich console display"""
    
    @staticmethod
    def show_banner():
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███╗   ███╗██╗████████╗██████╗ ███████╗                   ║
║   ████╗ ████║██║╚══██╔══╝██╔══██╗██╔════╝                   ║
║   ██╔████╔██║██║   ██║   ██████╔╝█████╗                     ║
║   ██║╚██╔╝██║██║   ██║   ██╔══██╗██╔══╝                     ║
║   ██║ ╚═╝ ██║██║   ██║   ██║  ██║███████╗                   ║
║   ╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝                   ║
║                                                               ║
║   ATT&CK Intelligence Framework v2.0                         ║
║   Advanced Threat Technique Analysis                         ║
║   Author: Orion | @N_Orion                                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold cyan", border_style="blue"))
    
    @staticmethod
    def show_techniques(techniques: List[Technique], limit: int = 50):
        """Display techniques in rich table"""
        if not techniques:
            console.print("[yellow]⚠ No techniques found matching criteria[/yellow]")
            return
        
        # Apply limit
        display_techniques = techniques[:limit]
        
        table = Table(
            title=f"MITRE ATT&CK Techniques (Showing {len(display_techniques)} of {len(techniques)})",
            show_header=True,
            header_style="bold magenta"
        )
        
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Name", style="green", width=30)
        table.add_column("Risk", justify="center", width=10)
        table.add_column("Tactics", width=20)
        table.add_column("Platforms", width=15)
        table.add_column("Description", width=40)
        
        for tech in display_techniques:
            risk_level, risk_score = tech.calculate_risk_score()
            
            # Color coding for risk
            risk_colors = {
                RiskLevel.CRITICAL: "red bold",
                RiskLevel.HIGH: "red",
                RiskLevel.MEDIUM: "yellow",
                RiskLevel.LOW: "green",
                RiskLevel.INFO: "blue"
            }
            risk_style = risk_colors.get(risk_level, "white")
            
            # Truncate long fields
            description = tech.description[:80] + "..." if len(tech.description) > 80 else tech.description
            tactics_str = ", ".join(tech.tactics[:2])
            if len(tech.tactics) > 2:
                tactics_str += f" +{len(tech.tactics)-2}"
            
            platforms_str = ", ".join(tech.platforms[:2])
            if len(tech.platforms) > 2:
                platforms_str += f" +{len(tech.platforms)-2}"
            
            table.add_row(
                tech.mitre_id,
                tech.name,
                f"[{risk_style}]{risk_level.value}[/]",
                tactics_str,
                platforms_str,
                description
            )
        
        console.print(table)
        
        if len(techniques) > limit:
            console.print(f"\n[dim]... and {len(techniques) - limit} more techniques[/dim]")
            console.print("[dim]Use --export to save all results[/dim]")
    
    @staticmethod
    def show_stats(techniques: List[Technique]):
        """Show statistics"""
        if not techniques:
            return
        
        # Risk distribution
        risk_dist = {}
        for tech in techniques:
            risk_level, _ = tech.calculate_risk_score()
            risk_dist[risk_level] = risk_dist.get(risk_level, 0) + 1
        
        # Tactics distribution
        tactic_dist = {}
        for tech in techniques:
            for tactic in tech.tactics:
                tactic_dist[tactic] = tactic_dist.get(tactic, 0) + 1
        
        # Platform distribution
        platform_dist = {}
        for tech in techniques:
            for platform in tech.platforms:
                platform_dist[platform] = platform_dist.get(platform, 0) + 1
        
        stats_table = Table(title="Statistics", show_header=True)
        stats_table.add_column("Category", style="cyan")
        stats_table.add_column("Count", justify="right", style="green")
        
        stats_table.add_row("Total Techniques", str(len(techniques)))
        stats_table.add_row("", "")
        
        for risk_level in RiskLevel:
            count = risk_dist.get(risk_level, 0)
            if count > 0:
                stats_table.add_row(f"Risk: {risk_level.value}", str(count))
        
        console.print(stats_table)


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class MitreAttackIntelligence:
    """Main application orchestrator"""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / ".mitre_attack"
        self.cache = CacheManager(self.cache_dir)
        self.fetcher = MitreAttackFetcher(self.cache)
        self.parser = TechniqueParser()
        self.techniques: List[Technique] = []
    
    async def initialize(self) -> bool:
        """Fetch and parse ATT&CK data"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Loading MITRE ATT&CK data...", total=None)
            
            data = await self.fetcher.fetch_enterprise_attack()
            if not data:
                console.print("[red]✗ Failed to fetch ATT&CK data[/red]")
                return False
            
            progress.update(task, description="Parsing techniques...")
            
            for obj in data.get("objects", []):
                technique = self.parser.parse_technique(obj)
                if technique:
                    self.techniques.append(technique)
            
            progress.update(task, description=f"✓ Loaded {len(self.techniques)} techniques")
        
        logger.info(f"Loaded {len(self.techniques)} techniques")
        return True
    
    def search(
        self,
        keyword: Optional[str] = None,
        tactics: Optional[List[str]] = None,
        platforms: Optional[List[str]] = None,
        min_risk: Optional[RiskLevel] = None,
        exclude_deprecated: bool = True,
        exclude_revoked: bool = True
    ) -> List[Technique]:
        """Search techniques with filters"""
        return self.parser.filter_techniques(
            self.techniques,
            keyword=keyword,
            tactics=tactics,
            platforms=platforms,
            min_risk=min_risk,
            exclude_deprecated=exclude_deprecated,
            exclude_revoked=exclude_revoked
        )


# ============================================================================
# CLI
# ============================================================================

app = typer.Typer(
    name="mitre-attack",
    help="MITRE ATT&CK Intelligence Framework - Advanced threat technique analysis",
    add_completion=False
)


@app.command()
def search(
    keyword: Optional[str] = typer.Option(None, "--keyword", "-k", help="Search keyword"),
    tactic: Optional[List[str]] = typer.Option(None, "--tactic", "-t", help="Filter by tactic (can specify multiple)"),
    platform: Optional[List[str]] = typer.Option(None, "--platform", "-p", help="Filter by platform"),
    min_risk: Optional[RiskLevel] = typer.Option(None, "--min-risk", "-r", help="Minimum risk level"),
    include_deprecated: bool = typer.Option(False, "--include-deprecated", help="Include deprecated techniques"),
    include_revoked: bool = typer.Option(False, "--include-revoked", help="Include revoked techniques"),
    limit: int = typer.Option(50, "--limit", "-l", help="Display limit"),
    export_csv: Optional[Path] = typer.Option(None, "--export-csv", help="Export to CSV"),
    export_json: Optional[Path] = typer.Option(None, "--export-json", help="Export to JSON"),
    export_markdown: Optional[Path] = typer.Option(None, "--export-md", help="Export to Markdown"),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show statistics"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Search MITRE ATT&CK techniques with advanced filters"""
    
    if verbose:
        logger.setLevel(logging.DEBUG)
    
    DisplayHandler.show_banner()
    
    # Initialize
    intel = MitreAttackIntelligence()
    
    async def run():
        if not await intel.initialize():
            raise typer.Exit(code=1)
        
        # Search
        results = intel.search(
            keyword=keyword,
            tactics=tactic,
            platforms=platform,
            min_risk=min_risk,
            exclude_deprecated=not include_deprecated,
            exclude_revoked=not include_revoked
        )
        
        console.print(f"\n[bold]Found {len(results)} techniques[/bold]\n")
        
        # Display
        if stats:
            DisplayHandler.show_stats(results)
        else:
            DisplayHandler.show_techniques(results, limit=limit)
        
        # Export
        if export_csv:
            ExportHandler.to_csv(results, export_csv)
        if export_json:
            ExportHandler.to_json(results, export_json)
        if export_markdown:
            ExportHandler.to_markdown(results, export_markdown)
    
    asyncio.run(run())


@app.command()
def clear_cache():
    """Clear local cache"""
    cache_dir = Path.home() / ".mitre_attack"
    cache = CacheManager(cache_dir)
    
    if Confirm.ask("Clear all cached data?"):
        cache.invalidate()
        console.print("[green]✓ Cache cleared[/green]")


@app.command()
def list_tactics():
    """List all MITRE ATT&CK tactics"""
    table = Table(title="MITRE ATT&CK Tactics")
    table.add_column("Phase", style="cyan")
    table.add_column("Name", style="green")
    
    for tactic in TacticPhase:
        table.add_row(tactic.value, tactic.name.replace("_", " ").title())
    
    console.print(table)


if __name__ == "__main__":
    app()
