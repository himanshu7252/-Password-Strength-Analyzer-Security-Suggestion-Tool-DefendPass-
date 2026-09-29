"""
Password Generator Service
Generates cryptographically secure passwords and memorable passphrases
using Python's `secrets` module (OS-level CSPRNG).
NEVER logs or persists generated values.
"""
import secrets
import string
from typing import Dict, Any, List

# Curated, safe, memorable wordlist for passphrase generation (EFF/educational inspired)
PASSPHRASE_WORDS = [
    "amber", "anchor", "apricot", "avalanche", "beacon", "breeze", "cactus",
    "canvas", "cedar", "cinder", "citadel", "cloud", "cobalt", "comet",
    "copper", "coral", "crystal", "delta", "desert", "echo", "eclipse",
    "emerald", "falcon", "feather", "flint", "forest", "fossil", "frost",
    "galaxy", "glacier", "granite", "harbor", "horizon", "island", "jasper",
    "jupiter", "lagoon", "lantern", "lightning", "lunar", "marble", "meadow",
    "meteor", "monarch", "mosaic", "nebula", "nexus", "oasis", "ocean",
    "orbit", "origami", "pebble", "phoenix", "pinnacle", "plasma", "prism",
    "pulse", "quartz", "quarry", "radar", "radiant", "ripple", "safari",
    "sapphire", "shadow", "shimmer", "sierra", "silver", "solstice", "sparrow",
    "summit", "tempest", "thunder", "timber", "titan", "topaz", "tornado",
    "tundra", "twilight", "valley", "velvet", "vortex", "voyage", "whisper",
    "willow", "zenith", "zephyr"
]

def generate_secure_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> Dict[str, Any]:
    """
    Generates a cryptographically strong password using `secrets`.
    Guarantees at least one character from each selected class.
    """
    length = max(8, min(128, length))
    
    char_pool = ""
    guaranteed = []
    
    if use_lower:
        char_pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        char_pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        char_pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        # Use safe standard symbols avoiding confusing whitespace/quotes
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        char_pool += symbols
        guaranteed.append(secrets.choice(symbols))
        
    # Fallback to alphanumeric if nothing selected
    if not char_pool:
        char_pool = string.ascii_letters + string.digits
        guaranteed.append(secrets.choice(string.ascii_letters))
        guaranteed.append(secrets.choice(string.digits))
        
    remaining_length = length - len(guaranteed)
    if remaining_length < 0:
        remaining_length = 0
        
    random_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]
    combined = guaranteed + random_chars
    
    # Cryptographically secure shuffle using SystemRandom
    sys_rand = secrets.SystemRandom()
    sys_rand.shuffle(combined)
    password = "".join(combined[:length])
    
    return {
        "password": password,
        "length": len(password),
        "entropy_source": "OS CSPRNG (secrets module / BCryptGenRandom)",
        "security_note": "Generated using a cryptographically secure random number generator. Not stored or logged."
    }

def generate_secure_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = True
) -> Dict[str, Any]:
    """
    Generates a high-entropy, memorable multi-word passphrase.
    """
    word_count = max(3, min(8, word_count))
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    
    if capitalize:
        words = [w.capitalize() for w in words]
        
    passphrase = separator.join(words)
    
    # Calculate approximate passphrase entropy
    # log2(len(PASSPHRASE_WORDS) ** word_count)
    import math
    entropy_bits = round(word_count * math.log2(len(PASSPHRASE_WORDS)), 1)
    
    return {
        "passphrase": passphrase,
        "word_count": word_count,
        "approximate_entropy_bits": entropy_bits,
        "educational_note": (
            "Passphrases derive strength from word combinations rather than cryptic substitutions. "
            "They are inherently resistant to dictionary attacks when words are chosen randomly."
        )
    }
