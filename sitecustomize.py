"""PhishingGuard V2 Keras compatibility loader.

Compatibility-only patch for the saved CNN preprocessing vocabulary. It removes
only repeated empty-string mask tokens while preserving token order and does not
retrain or intentionally alter learned CNN weights.
"""


def _clean_vocabulary(vocabulary):
    try:
        values = list(vocabulary)
    except TypeError:
        return vocabulary, False

    cleaned = []
    seen_empty = False
    changed = False
    for value in values:
        try:
            is_empty = str(value) == ""
        except Exception:
            is_empty = False
        if is_empty:
            if seen_empty:
                changed = True
                continue
            seen_empty = True
        cleaned.append(value)
    return (cleaned if changed else vocabulary), changed


def _patch_class(cls, label):
    original = cls.set_vocabulary
    if getattr(original, "_phishingguard_v2_patch", False):
        return

    def patched(self, vocabulary, *args, **kwargs):
        vocabulary, changed = _clean_vocabulary(vocabulary)
        if changed:
            print(f"PhishingGuard V2 compatibility: removed duplicate empty vocabulary token via {label}.")
        return original(self, vocabulary, *args, **kwargs)

    patched._phishingguard_v2_patch = True
    cls.set_vocabulary = patched


try:
    # Patch the public TensorFlow/Keras alias.
    import tensorflow as tf
    _patch_class(tf.keras.layers.StringLookup, "tf.keras")

    # Keras deserialization may instantiate the internal class directly rather
    # than the public alias, so patch that exact implementation too.
    try:
        from keras.src.layers.preprocessing.string_lookup import StringLookup as InternalStringLookup
        _patch_class(InternalStringLookup, "keras.src")
    except Exception as internal_exc:
        print(f"PhishingGuard V2 internal Keras patch note: {internal_exc}")

    print("PhishingGuard V2 Keras compatibility shim active (public + internal loader).")
except Exception as exc:
    print(f"PhishingGuard V2 compatibility shim could not initialise: {exc}")
