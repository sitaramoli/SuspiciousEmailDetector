import re

from scapy.packet import Raw


class IMAPParser:
    def parse_session(self, packets):
        email_data = {
            'protocol': 'IMAP',
            'attachments': [],
            'body': ''
        }

        raw_data = b"".join(p[Raw].load for p in packets if Raw in p)

        # Detect IMAP FETCH commands
        if b'FETCH' in raw_data:
            self._parse_imap_fetch(raw_data, email_data)

        return email_data

    def _parse_imap_fetch(self, raw_data, email_data):
        try:
            decoded = raw_data.decode('utf-8', errors='replace')

            if 'BODYSTRUCTURE (' in decoded:
                parts = decoded.split('BODYSTRUCTURE (')[1].split(')')[0]
                for match in re.finditer(r'name="?(.*?)"?\)', parts):
                    email_data['attachments'].append({
                        'filename': match.group(1),
                        'content-type': 'application/octet-stream'
                    })

        except Exception as e:
            print(f"IMAP parsing error: {str(e)}")
