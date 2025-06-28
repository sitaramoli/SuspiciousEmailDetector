import re
from urllib.parse import urlparse

INDICATORS = [
    # Urgency indicators
    {
        'type': 'Urgency Language',
        'patterns': [
            re.compile(r'\b(urgent|immediate|action required|right away|asap|quick response|test)\b', re.IGNORECASE),
            re.compile(r'\b(account (verification|suspended)|verify (now|immediately)|security alert)\b',
                       re.IGNORECASE),
            re.compile(r'\b(limited time offer|expiring soon|last chance|final notice)\b', re.IGNORECASE)
        ]
    },

    # Suspicious sender patterns
    {
        'type': 'Spoofed Sender',
        'patterns': [
            re.compile(r'(@paypal|@amazon|@microsoft|@apple|@bankofamerica|@wellsfargo|@chase)\.(com|net|org)',
                       re.IGNORECASE),
            re.compile(r'no[-_]?reply@|donotreply@|noreply@', re.IGNORECASE)
        ]
    },

    # Suspicious content patterns
    {
        'type': 'Suspicious Content',
        'patterns': [
            re.compile(r'\b(password|login|credentials|account (details|information)|social security|ssn)\b',
                       re.IGNORECASE),
            re.compile(r'\b(click (here|below)|follow this link|update your (account|information))\b', re.IGNORECASE),
            re.compile(r'\b(wire transfer|bank transfer|payment request|invoice attached)\b', re.IGNORECASE)
        ]
    },

    # URL patterns
    {
        'type': 'Suspicious URL',
        'patterns': [
            re.compile(r'(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)'),
        ],
        'checks': [
            # Check if the URL uses a known URL shortener
            lambda x: any(short in urlparse(x.lower()).netloc
                          for short in
                          ['bit.ly', 'tinyurl', 'goo.gl', 'shorte.st', 't.co', 'ow.ly', 'is.gd', 'buff.ly']),

            # Check if it impersonates a trusted brand but is not the official domain
            lambda x: any(
                brand in urlparse(x.lower()).netloc.split('.')[-2]
                and not urlparse(x.lower()).netloc.endswith((f"{brand}.com", f"www.{brand}.com"))
                for brand in ['paypal', 'amazon', 'bankofamerica', 'apple', 'microsoft', 'google', 'facebook']
            ),

            # Check for suspicious TLDs
            lambda x: urlparse(x.lower()).netloc.split('.')[-1] in ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'ru', 'cn',
                                                                    'top'],

            # Check if subdomain is numeric (e.g., 12345.example.com)
            lambda x: any(part.isdigit() for part in urlparse(x.lower()).netloc.split('.')[:-2])
        ]
    },

    # Attachment patterns
    {
        'type': 'Malicious Attachment',
        'patterns': [
            re.compile(r'.*\.(exe|bat|js|vbs|ps1|jar|scr|msi|cmd|hta|zip|rar|7z)$', re.IGNORECASE),
            re.compile(r'^(invoice|document|scan|details)\.(pdf|doc|docx|xls|xlsx)', re.IGNORECASE)
        ]
    },
    {
        'type': 'Double Extension',
        'patterns': [
            re.compile(r'.*\.(txt|pdf|doc)\.(exe|js|vbs)$', re.IGNORECASE)
        ]
    }
]


def detect_suspicious_indicators(email_data):
    """Enhanced email threat detection"""
    threats = []

    # Check sender address
    if 'from' in email_data:
        threats.extend(_check_field(email_data['from'], 'Sender'))

    # Check recipient addresses
    if 'to' in email_data:
        if isinstance(email_data['to'], list):
            for recipient in email_data['to']:
                threats.extend(_check_field(recipient, 'Recipient'))
        else:
            threats.extend(_check_field(email_data['to'], 'Recipient'))

    # Check subject
    if 'subject' in email_data:
        threats.extend(_check_field(email_data['subject'], 'Subject'))

    # Check body
    if 'body' in email_data:
        threats.extend(_check_field(email_data['body'], 'Body'))

    # Check attachments
    if 'attachments' in email_data:
        for attachment in email_data['attachments']:
            if 'filename' in attachment:
                threats.extend(_check_field(attachment['filename'], 'Attachment'))

    return threats


def _check_field(content, context):
    """Check a specific email field for threats"""
    threats = []

    if not content:
        return threats

    for indicator in INDICATORS:
        # Check patterns
        if 'patterns' in indicator:
            for pattern in indicator['patterns']:
                matches = pattern.findall(str(content))
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):  # Handle regex groups
                            match = next((m for m in match if m), '')
                        if match:
                            threats.append({
                                'type': indicator['type'],
                                'value': str(match)[:100] + ('...' if len(str(match)) > 100 else ''),
                                'context': context
                            })

        # Run additional checks (like for URLs)
        if 'checks' in indicator and context in ['Body', 'Subject']:
            if 'patterns' in indicator:  # For URL checks
                for pattern in indicator['patterns']:
                    matches = pattern.findall(str(content))
                    for match in matches:
                        if isinstance(match, tuple):
                            match = next((m for m in match if m), '')
                        if match:
                            for check in indicator['checks']:
                                try:
                                    if check(match):
                                        threats.append({
                                            'type': f"{indicator['type']}",
                                            'value': str(match)[:100] + ('...' if len(str(match)) > 100 else ''),
                                            'context': context,

                                        })
                                except:
                                    continue

    return threats
