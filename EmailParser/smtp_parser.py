import re
from email.utils import parsedate_to_datetime, parseaddr


class SMTPParser:
    def parse_session(self, packets):
        email_data = {
            'to': [],
            'from': '',
            'date': 'Unknown',
            'subject': 'No Subject',
            'attachments': [],
            'body': ''
        }
        email_raw = b""
        in_data = False

        for packet in packets:
            try:
                if not packet.haslayer('TCP') or not packet.haslayer('Raw'):
                    continue

                payload = bytes(packet['Raw'].load)

                if not in_data:
                    decoded = payload.decode('ascii', errors='ignore').strip()
                    if decoded.startswith('DATA'):
                        in_data = True
                        continue

                if in_data:
                    email_raw += payload
                    if not email_data.get('headers_extracted', False):
                        self._extract_headers_from_data(email_raw, email_data)

            except Exception:
                continue

        if email_raw:
            self._parse_attachments_from_data(email_raw, email_data)
            self._extract_body(email_raw, email_data)

        return email_data

    def _parse_attachments_from_data(self, raw_data, email_data):
        """Parse MIME attachments from raw DATA"""
        try:
            data_str = raw_data.decode('utf-8', errors='replace')

            # Find MIME boundary
            boundary_match = re.search(r'boundary="?(.*?)"?', data_str)
            if not boundary_match:
                return

            boundary = '--' + boundary_match.group(1)
            parts = data_str.split(boundary)

            for part in parts[1:-1]:  # Skip preamble and epilogue
                if 'Content-Disposition: attachment' not in part and \
                        'Content-Disposition: inline' not in part:
                    continue

                # Extract attachment metadata
                filename_match = re.search(r'filename="?(.*?)"?\s*(?:\r\n|\n|;)', part)
                content_type_match = re.search(r'Content-Type:\s*(.*?);', part)
                encoding_match = re.search(r'Content-Transfer-Encoding:\s*(.*?)\s*(?:\r\n|\n)', part)

                if filename_match and content_type_match:
                    attachment = {
                        'filename': filename_match.group(1),
                        'content-type': content_type_match.group(1).strip(),
                        'encoding': encoding_match.group(1).strip() if encoding_match else '7bit'
                    }
                    email_data['attachments'].append(attachment)

        except Exception:
            pass

    def _extract_headers_from_data(self, raw_data, email_data):
        """Extract headers from the raw email data"""
        try:
            data_str = raw_data.decode('ascii', errors='ignore')

            # Extract From, To, Date, Subject from headers
            headers_end = data_str.find('\r\n\r\n') or data_str.find('\n\n')
            if headers_end > 0:
                headers = data_str[:headers_end]

                from_match = re.search(r'^From:\s*(.*?)\r?$', headers, re.IGNORECASE | re.MULTILINE)
                to_match = re.search(r'^To:\s*(.*?)\r?$', headers, re.IGNORECASE | re.MULTILINE)
                date_match = re.search(r'^Date:\s*(.*?)\r?$', headers, re.IGNORECASE | re.MULTILINE)
                subject_match = re.search(r'^Subject:\s*(.*?)\r?$', headers, re.IGNORECASE | re.MULTILINE)

                if from_match:
                    email_data['from'] = self._clean_email(from_match.group(1))
                if to_match:
                    email_data['to'] = self._split_emails(to_match.group(1))
                if date_match:
                    email_data['date'] = self._format_date(date_match.group(1))
                if subject_match:
                    email_data['subject'] = subject_match.group(1).strip()

                email_data['headers_extracted'] = True

        except Exception:
            pass

    def _extract_body(self, raw_data, email_data):
        """Extract the main email body text"""
        try:
            data_str = raw_data.decode('utf-8', errors='replace')
            body_start = data_str.find('\r\n\r\n') or data_str.find('\n\n')
            if body_start > 0:
                email_data['body'] = data_str[body_start:].strip()
        except Exception:
            pass

    def _clean_email(self, text):
        """Extract just the email address"""
        _, addr = parseaddr(text)
        return addr if '@' in addr else text.strip()

    def _split_emails(self, text):
        """Split multiple email addresses"""
        return [self._clean_email(a) for a in text.split(',') if '@' in a]

    def _format_date(self, date_str):
        """Standardize date format"""
        try:
            return parsedate_to_datetime(date_str).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return date_str.strip()
