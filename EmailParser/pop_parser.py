import re

from rich import console
from scapy.packet import Raw


class POPParser:
    def parse_session(self, packets):
        email_data = {
            'protocol': 'pop',
            'from': '',
            'to': [],
            'subject': '',
            'date': '',
            'body': '',
            'attachments': [],
            'headers': {}
        }

        try:
            # Combine all packets with Raw layer
            raw_data = b''.join(p[Raw].load for p in packets if Raw in p)
            decoded = raw_data.decode('utf-8', errors='replace')

            # Extract the actual email content (after RETR response)
            if '+OK' in decoded and 'RETR' in decoded:
                email_content = decoded.split('RETR', 1)[1].split('\r\n', 1)[1]

                # Parse headers and body
                header_end = email_content.find('\r\n\r\n')
                if header_end > 0:
                    headers = email_content[:header_end]
                    email_data['body'] = email_content[header_end:].strip()

                    # Parse important headers
                    for line in headers.split('\r\n'):
                        if line.startswith('From:'):
                            email_data['from'] = line[5:].strip()
                        elif line.startswith('To:'):
                            email_data['to'] = [addr.strip() for addr in line[3:].split(',')]
                        elif line.startswith('Subject:'):
                            email_data['subject'] = line[8:].strip()
                        elif line.startswith('Date:'):
                            email_data['date'] = line[5:].strip()

                # Parse attachments from MIME boundaries
                boundary = None
                for line in headers.split('\r\n'):
                    if 'boundary=' in line:
                        boundary = line.split('boundary=')[1].strip('"')
                        break

                if boundary:
                    parts = email_content.split('--' + boundary)
                    for part in parts:
                        if 'Content-Disposition: attachment' in part or 'filename=' in part:
                            filename = re.search(r'filename="?(.*?)"?[\s;]', part)
                            content_type = re.search(r'Content-Type:\s*(.*?);', part)
                            if filename:
                                email_data['attachments'].append({
                                    'filename': filename.group(1),
                                    'content-type': content_type.group(
                                        1).strip() if content_type else 'application/octet-stream'
                                })

            return email_data

        except Exception as e:
            console.print(f"[red]POP parsing error:[/red] {str(e)}")
            return None
