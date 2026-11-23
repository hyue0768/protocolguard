"""Small source-only example for conservative context collection."""

def parse_length(value):
    return int(value)


def handle_message(value):
    length = parse_length(value)
    if length < 0:
        return False
    return True
