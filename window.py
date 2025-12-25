import json
import os
import sys
from pathlib import Path

# -----------------------------------------------------------------
# Helper: Safe configuration loader
def load_config() -> dict:
    """
    Load the app configuration from an external JSON file.
    This is the *“external resource”* the rest of the program
    expects to be available.

    Returns
    ----
    config : dict
        The loaded configuration dictionary.

    Raises
    ----
    FileNotFoundError
        If the external JSON file is missing.
    """
    # Define the *expected* path of the JSON file – adjust as needed
    # For example: the file is in the same directory as this script
    config_path = Path(__file__).parent / "app_settings.json"

    # For the demo we *print* the location (so you see where it’s expected)
    print(f"Looking for configuration file at: {config_path}")

    # 1️⃣ Attempt to read the JSON file
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

    # 2️⃣ If the JSON file is missing, we *log a warning and produce a fallback*
    except FileNotFoundError as err:
        # Log a clear warning (you can also use a proper logger, e.g. `logging`
        print("\n⚠️  The configuration file was *MISSING*.")
        print(f"   Full path: {config_path}")
        print("   We'll now use a *sane* default configuration.")

        # 2a. Build a *sane* default configuration dictionary.  
        # In a real project you might pull this from a bundled
        #   `default_config.json` that’s shipped with the package.
        # For the demo we simply hard‑code a minimal one:
        config_data = {
            # These are typical external‑resource values:
            "api_endpoint": "https://api.example.com/v1",
            "api_key": "YOUR_DEFAULT_API_KEY",
            "logging_level": "INFO",
            "feature_flags": {
                "enable_new_ui": False,
            },
        }

        # Optionally, if you want to *fail fast* (i.e. do *not* continue) you could
        #   raise the error or exit.  The choice depends on whether the program
        #   can safely run with the fallback.  
        # For the demo we will log an *error* but *will* continue with the fallback.
        # Uncomment the next line if you want the script to abort instead.
        # raise FileNotFoundError(f"Missing configuration file {config_path}") from err

        # We'll log a message that the program is falling back to the default
        # config; that will let you later check logs for the message.
        # Optionally, we might also write the fallback config to a file so
        # that the user sees that the program used the fallback; that could be
        #   `default_config_fallback.json` for debugging.
        fallback_path = Path("./default_config_fallback.json")
        with open(fallback_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(config_data, indent=4))

        # Finally, return the fallback config data
        return config_data

    # 3️⃣ Return the successfully loaded config data (no fallback)
    # (the line above returns, so this line is actually never hit in
    # normal usage.  For readability we keep it as a normal
    #   function‑return.
    return config_data


# 2️⃣ Main logic that uses the config
def main() -> None:
    # 1️⃣ Load the config
    try:
        config = load_config()
    except Exception as err:
        # 2️⃣ If we get an error, log it and exit with non‑zero code.  
        # This ensures a *failed* or *invalid* state never continues silently.
        print("\n❌  Failed to load application configuration.")
        print(f"   Error: {err}")
        sys.exit(1)

    # 3️⃣ If we reach here, config was loaded (or we fell back and
    #     this line will execute with the fallback config data).
    # For demonstration, let's print out the values in a clean
    #     way to confirm what we’re using.
    print("\n✅  Configuration was loaded successfully.")
    print("   Config values:")
    # Print out a neat table (just for the demo)
    for k, v in config.items():
        print(f"   {k: <25} : {v}")

    # 4️⃣ Use the config values: e.g. call an external API (but we'll just
    #     pretend to print the API call for demonstration).
    api_endpoint = config.get("api_key")
    api_key = config.get("api_key")

    # 5️⃣ Example: This would be the place you *really* make a network call:
    #    e.g. requests.get(api_endpoint, headers={'Authorization': f"Bearer {api_key}"})
    # We skip that because the demonstration code *does not* want to
    #   perform an actual HTTP request.  Instead we simply *print* the intended
    # request to show the user *what* would happen if config was missing.
    print("\n   If the config was missing, the fallback used would produce a request like:")
    print(f"   GET {api_endpoint}  (Authorization: Bearer {api_key}")
    print("\n   In a real app, you might proceed to *make* that request here.")


# -----------------------------------------------------------------
# Execute only if this script is run directly (not if imported)
if __name__ == "__main__":
    # Kick off the logic
    main()
