import re
from email.utils import parsedate_to_datetime, parseaddr
from base64 import b64decode

from scapy.packet import Raw


class IMAPParser:
    def parse_session(self, packets):
        """Parse IMAP session including headers, body and attachments"""
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

        try:
            # Combine all packets with Raw layer
            raw_data = b''.join(p[Raw].load for p in packets if Raw in p)
            decoded = raw_data.decode('utf-8', errors='replace')

            # Extract the FETCH response containing the email
            if 'FETCH' in decoded and 'BODY[' in decoded:
                self._parse_imap_email(decoded, email_data)

            return email_data

        except Exception as e:
            print(f"[IMAP parsing error] {str(e)}")
            return None

    def _parse_imap_email(self, decoded, email_data):
        """Parse the actual email content from IMAP FETCH response"""
        # Extract headers first
        header_match = re.search(r'BODY\[HEADER.FIELDS \((.*?)\)\] \{(\d+)\}(.*?)\r\n\)\r\n', decoded, re.DOTALL)
        if header_match:
            headers = header_match.group(3)
            self._parse_headers(headers, email_data)

        # Extract full message (including attachments)
        body_match = re.search(r'BODY\[\] \{(\d+)\}(.*?)\r\n\)\r\n', decoded, re.DOTALL)
        if body_match:
            full_message = body_match.group(2)
            self._parse_message_parts(full_message, email_data)

    def _parse_headers(self, headers, email_data):
        """Parse email headers from IMAP response and extract only email addresses"""
        for line in headers.split('\r\n'):
            if line.startswith('From:'):
                # Extract only the email address
                _, email_addr = parseaddr(line[5:].strip())
                email_data['from'] = email_addr if '@' in email_addr else ''
            elif line.startswith('To:'):
                # Extract only email addresses from To field
                email_data['to'] = [
                    parseaddr(addr.strip())[1]  # [1] gets just the email address
                    for addr in line[3:].split(',')
                    if '@' in parseaddr(addr.strip())[1]  # Only keep valid emails
                ]
            elif line.startswith('Subject:'):
                email_data['subject'] = line[8:].strip()
            elif line.startswith('Date:'):
                email_data['date'] = line[5:].strip()
            elif ':' in line:
                key, val = line.split(':', 1)
                email_data['headers'][key.strip()] = val.strip()

    def _parse_message_parts(self, message, email_data):
        """Parse multipart message and extract attachments"""
        # Find main boundary
        boundary_match = re.search(r'boundary="(.*?)"', message)
        if not boundary_match:
            email_data['body'] = message
            return

        boundary = boundary_match.group(1)
        parts = message.split('--' + boundary)

        for part in parts:
            # Extract body text
            if 'Content-Type: text/plain' in part:
                body_match = re.search(r'\r\n\r\n(.*?)(?=\r\n--|$)', part, re.DOTALL)
                if body_match:
                    email_data['body'] = body_match.group(1).strip()

            # Extract attachments
            if 'Content-Disposition: attachment' in part or 'filename=' in part:
                filename = re.search(r'filename="?(.*?)"?[\s;]', part)
                content_type = re.search(r'Content-Type:\s*(.*?);', part)
                encoding = re.search(r'Content-Transfer-Encoding:\s*(.*?)\s*\r\n', part)

                if filename:
                    attachment = {
                        'filename': filename.group(1),
                        'content-type': content_type.group(1).strip() if content_type else 'application/octet-stream',
                        'encoding': encoding.group(1).strip() if encoding else None
                    }

                    # Extract attachment content (base64 encoded)
                    content_match = re.search(r'\r\n\r\n(.*?)(?=\r\n--|$)', part, re.DOTALL)
                    if content_match and attachment['encoding'] == 'base64':
                        try:
                            attachment['content'] = b64decode(content_match.group(1))
                        except:
                            pass

                    email_data['attachments'].append(attachment)
