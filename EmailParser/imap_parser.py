import re
from email import message_from_string
from email.utils import parsedate_to_datetime, parseaddr

from scapy.packet import Raw


class IMAPParser:
    def parse_session(self, packets):
        """Parse IMAP session and return a list of emails"""
        parsed_emails = []

        try:
            raw_data = b''.join(p[Raw].load for p in packets if Raw in p)
            decoded = raw_data.decode('utf-8', errors='replace')

            # Find all FETCH blocks with BODY[] {length}
            fetch_pattern = re.compile(r'BODY\[\] \{(\d+)\}\r\n', re.DOTALL)
            pos = 0

            while True:
                match = fetch_pattern.search(decoded, pos)
                if not match:
                    break

                length = int(match.group(1))
                start = match.end()
                raw_email = decoded[start:start + length]

                if len(raw_email) < length:
                    print(f"[WARNING] Incomplete email: expected {length}, got {len(raw_email)}")
                    break

                email_data = {
                    'protocol': 'imap',
                    'from': '',
                    'to': [],
                    'subject': '',
                    'date': '',
                    'body': '',
                    'attachments': [],
                    'headers': {}
                }

                self._parse_message(raw_email, email_data)
                parsed_emails.append(email_data)

                # Move cursor ahead for next match
                pos = start + length

        except Exception as e:
            print(f"[IMAP session parsing error] {e}")

        return parsed_emails

    def _parse_message(self, raw_email, email_data):
        try:
            msg = message_from_string(raw_email)

            email_data['headers'] = dict(msg.items())
            email_data['from'] = parseaddr(msg.get('From'))[1]
            email_data['to'] = [parseaddr(msg.get('To'))[1]] if msg.get('To') else []
            email_data['subject'] = msg.get('Subject', '')
            email_data['date'] = str(parsedate_to_datetime(msg.get('Date'))) if msg.get('Date') else ''

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition = str(part.get("Content-Disposition", "")).lower()

                    if "attachment" in disposition or part.get_filename():
                        attachment = {
                            'filename': part.get_filename(),
                            'content-type': content_type,
                            'encoding': part.get("Content-Transfer-Encoding", ""),
                            'content': part.get_payload(decode=True)
                        }
                        email_data['attachments'].append(attachment)

                    elif content_type == "text/plain" and "attachment" not in disposition:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            email_data['body'] += part.get_payload(decode=True).decode(charset, errors='replace')
                        except Exception:
                            continue
            else:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    email_data['body'] = payload.decode('utf-8', errors='replace')
                else:
                    email_data['body'] = payload

        except Exception as e:
            print(f"[Message parsing error] {e}")
