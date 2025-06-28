from rich.align import Align
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.panel import Panel
from rich.box import ROUNDED, SIMPLE

from EmailParser.imap_parser import IMAPParser
from EmailParser.pop_parser import POPParser
from EmailParser.smtp_parser import SMTPParser
from utils.pcap_utils import extract_email_sessions
from utils.threat_indicators import detect_suspicious_indicators

# Initialize console
console = Console()


def analyze_pcap_files(folder_path, logs):
    """Analyze all pcapng files in a folder"""

    try:
        pcap_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.pcapng')]
    except Exception as err:
        console.print(f"[red]Error reading directory:[/red] {str(err)}")
        return

    if not pcap_files:
        console.print(f"[yellow]No pcapng files found in {folder_path}[/yellow]")
        return

    all_results = []
    processed_files = 0

    for pcap_file in track(pcap_files, description="🔎  Starting Analysis...\n"):
        full_path = os.path.join(folder_path, pcap_file)
        try:
            results = analyze_pcap_file(full_path)
            if results:
                all_results.extend(results)
                processed_files += 1
        except Exception as err:
            console.print(f"[red]Error analyzing {pcap_file}:[/red] {str(err)}")
            continue

    # Display summary
    console.print(f" ✅ Analysis Complete : "
                  f"Found [red]{len(all_results)}[/red] suspicious emails in [bold]{len(pcap_files)}[/bold] files\n")
    console.print()

    if all_results:
        display_results(all_results)
        save_combined_report(all_results, logs)


def analyze_pcap_file(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        sessions = extract_email_sessions(packets)

        suspicious_emails = []
        for session in sessions:
            protocol = session['protocol']
            session_packets = session['packets']

            # Initialize appropriate parser
            if protocol == 'smtp':
                parser = SMTPParser()
            elif protocol == 'pop':
                parser = POPParser()
            elif protocol == 'imap':
                parser = IMAPParser()
            else:
                continue

            try:
                email_data = parser.parse_session(session_packets)
                if email_data:
                    email_data.update({
                        'source_file': os.path.basename(pcap_file),
                        'protocol': protocol
                    })
                    threats = detect_suspicious_indicators(email_data)
                    if threats:
                        email_data['threats'] = threats
                        suspicious_emails.append(email_data)
            except Exception as err:
                console.print(f"[yellow]Warning parsing {protocol} session:[/yellow] {str(err)}")
                continue

        return suspicious_emails

    except Exception as err:
        console.print(f"[red]Error analyzing {os.path.basename(pcap_file)}:[/red] {str(err)}")
        return None


def display_results(results):
    """Display results in beautifully formatted rich tables"""
    # Main title panel
    console.print(Panel(
        Align.center("SUSPICIOUS EMAIL ANALYSIS RESULTS"),
        style="bold white on red",
        expand=True
    ))
    console.print()

    # Group by source file
    results_by_file = {}
    for email in results:
        if email['source_file'] not in results_by_file:
            results_by_file[email['source_file']] = []
        results_by_file[email['source_file']].append(email)

    for file_name, emails in results_by_file.items():
        # File header panel
        console.print(f"⚠️  [bold red]{len(emails)}[/bold red] Suspicious Emails Found in [bold]{file_name}[/bold]\n")

        for i, email in enumerate(emails, 1):
            # Main email table
            email_table = Table(
                title=f"✉️  Email #{i}",
                show_header=True,
                header_style="bold bright_white on dark_blue",
                border_style="bright_white",
                box=ROUNDED,
                expand=True
            )
            email_table.add_column("Field", style="bold cyan", width=15)
            email_table.add_column("Value", style="white")

            # Format date
            email_date = email.get('date', 'Unknown')
            if email_date != 'Unknown':
                try:
                    from email.utils import parsedate_to_datetime
                    email_date = parsedate_to_datetime(email_date).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass

            # Add email metadata
            email_table.add_row(
                "[bold]From[/bold]",
                f"[green]{email.get('from', 'N/A')}[/green]"
            )
            email_table.add_row(
                "[bold]To[/bold]",
                f"[yellow]{', '.join(email['to']) if isinstance(email.get('to'), list) else email.get('to', 'N/A')}[/yellow]"
            )
            email_table.add_row(
                "[bold]Subject[/bold]",
                f"[magenta]{email.get('subject', 'No Subject')}[/magenta]"
            )
            email_table.add_row(
                "[bold]Date[/bold]",
                f"[blue]{email_date}[/blue]"
            )

            # Threats table
            if email.get('threats'):
                threats_table = Table(
                    box=SIMPLE,
                    show_header=True,
                    header_style="bold red",
                    style="red"
                )
                threats_table.add_column("Threat Type", style="bold")
                threats_table.add_column("Details")

                for threat in email['threats']:
                    threats_table.add_row(
                        threat['type'],
                        threat['value']
                    )

                email_table.add_row(
                    "[bold red]Threats[/bold red]",
                    threats_table
                )

            # Attachments table
            if email.get('attachments'):
                attachments_table = Table(
                    box=SIMPLE,
                    show_header=True,
                    header_style="bold bright_yellow"
                )
                attachments_table.add_column("Filename")
                attachments_table.add_column("Type")

                for a in email['attachments']:
                    attachments_table.add_row(
                        f"[bright_cyan]{a['filename']}[/bright_cyan]",
                        a['content-type']
                    )

                email_table.add_row(
                    "[bold yellow]Attachments[/bold yellow]",
                    attachments_table
                )

            # Print the email table with spacing
            console.print(email_table)
            console.print()  # Add extra space between emails


def save_combined_report(results, folder_path):
    """Save comprehensive report to file"""

    os.makedirs(folder_path, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"email_analysis_log_{timestamp}.txt"
    report_path = os.path.join(folder_path, report_filename)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Email Threat Analysis Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Files Analyzed: {len({r['source_file'] for r in results})}\n")
            f.write(f"Total Suspicious Emails: {len(results)}\n")
            f.write("=" * 80 + "\n\n")

            for email in results:
                f.write(f"Source File: {email['source_file']}\n")
                f.write(f"From: {email.get('from', 'N/A')}\n")
                f.write(f"To: {email.get('to', 'N/A')}\n")
                f.write(f"Subject: {email.get('subject', 'No Subject')}\n")
                f.write(f"Date: {email.get('date', 'Unknown')}\n\n")

                f.write("Threat Indicators:\n")
                for threat in email['threats']:
                    f.write(f"- {threat['type']}\n")
                    f.write(f"  Value: {threat['value']}\n")
                    f.write(f"  Context: {threat.get('context', 'N/A')}\n\n")

                if email.get('attachments'):
                    f.write("Attachments:\n")
                    for a in email['attachments']:
                        f.write(f"- {a['filename']} ({a['content-type']})\n")
                    f.write("\n")

                f.write("Body Preview:\n")
                body = email.get('body', 'No body content')
                f.write(body[:1000].strip() + ('...' if len(body) > 1000 else ''))
                f.write("\n\n" + "=" * 80 + "\n\n")

        console.print(f"📁 Analysis report saved to [bold]{report_path}[/bold]")
    except Exception as err:
        console.print(f"[red]Error saving report:[/red] {str(err)}")


if __name__ == "__main__":
    file_path = 'PacketFiles'
    log_path = 'AnalysisReports'

    try:
        analyze_pcap_files(file_path, log_path)
    except KeyboardInterrupt:
        console.print("\n[red]Analysis interrupted by user[/red]")
    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {str(e)}")
