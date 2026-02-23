import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import our engine from the src package
from src.quantumguard import analyze_tls_handshake

app = typer.Typer(help="QuantumGuard: Post-Quantum Cryptography Auditor")
console = Console()

@app.command()
def scan(
    hostname: str = typer.Argument(..., help="Target hostname to scan (e.g., cloudflare.com)"),
    port: int = typer.Option(443, "--port", "-p", help="Target port (default: 443)")
):
    """
    Perform a TLS 1.3 Handshake audit to determine Quantum Readiness.
    """
    # 1. Print a beautiful header
    console.print(
        Panel(
            f"[bold blue] QuantumGuard PQC Scanner[/bold blue]\n"
            f"Targeting: [bold white]{hostname}:{port}[/bold white]\n"
            f"Mode: Active TLS 1.3 Handshake Probing", 
            expand=False
        )
    )
    
    # 2. Show a loading spinner while the network I/O happens
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description=f"Initiating Quantum-Aware Handshake with {hostname}...", total=None)
        
        # Call our Master's level Scapy logic
        result = analyze_tls_handshake(hostname, port)
        
    # 3. Handle Network and Protocol Errors
    if result.get("status") in ["error", "unknown"]:
        console.print(f"[bold red]❌ Scan Failed:[/bold red] {result.get('message')}")
        raise typer.Exit(1)
        
    # 4. Parse the Success Data
    group_id = result.get("group_id")
    info = result.get("info", {})
    scan_type = result.get("type")
    
    # 5. Build the Output Table
    table = Table(title=f"Quantum Readiness Report: {hostname}")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Result", style="white")
    
    # Format the Hex ID nicely
    hex_str = f"0x{group_id:04x}" if group_id else "N/A"
    table.add_row("Server Selected Group", f"[bold]{hex_str}[/bold]")
    table.add_row("Algorithm Name", info.get("name", "Unknown"))
    
    # Color-code the security status based on grade
    grade = info.get("grade", "F")
    if grade in ["A+", "A"]:
        status_color = "bold green"
    elif grade == "B":
        status_color = "bold yellow"
    else:
        status_color = "bold red"
        
    table.add_row("Security Status", f"[{status_color}]{info.get('status', 'Unknown')}[/{status_color}]")
    table.add_row("Crypto-Agility Grade", f"[{status_color}]{grade}[/{status_color}]")
    table.add_row("Handshake Evidence", f"[italic]{scan_type}[/italic]")
    
    # 6. Render the Table
    console.print("\n")
    console.print(table)
    console.print("\n")
    
    # 7. Final Verdicts
    console.print("\n")
    if grade in ["A+", "A"]:
        console.print(f"[bold green]PASS:[/bold green] {hostname} is prepared for Y2Q. Hybrid Key Exchange negotiated.")
    elif grade == "B":
        console.print(f"[bold yellow]QUANTUM WARNING:[/bold yellow] {hostname} uses strong classical crypto (TLS 1.3), but is vulnerable to [italic]Store-Now-Decrypt-Later (SNDL)[/italic] quantum attacks.")
    else:
        console.print(f"[bold red]CRITICAL FAILURE:[/bold red] {hostname} failed to negotiate TLS 1.3 or modern Key Shares. It is vulnerable to both Classical Protocol Downgrades and Future Quantum Impersonation.")

if __name__ == "__main__":
    app()