"""Compatibility shim for the PhishingGuard V2 saved Keras model.

The model was saved by a Keras version that serialized the TextVectorization
vocabulary with a duplicate empty-string mask token. Newer Keras rejects that
vocabulary while deserializing StringLookup. This shim removes only duplicate
empty-string entries at load time. It does not retrain the model or modify any
learned CNN weights.
"""

try:
    import tensorflow as tf

    _StringLookup = tf.keras.layers.StringLookup
    _original_set_vocabulary = _StringLookup.set_vocabulary

    def _compat_set_vocabulary(self, vocabulary, *args, **kwargs):
        try:
            values = list(vocabulary)
        except TypeError:
            return _original_set_vocabulary(self, vocabulary, *args, **kwargs)

        # Keras reserves the empty string as the mask token. Some older saved
        # TextVectorization assets contain it more than once; current Keras
        # raises before the model can load. Preserve order and remove only
        # repeated empty-string entries, leaving all real tokens untouched.
        cleaned = []
        seen_empty = False
        changed = False
        for value in values:
            is_empty = False
            try:
                is_empty = str(value) == ""
            except Exception:
                pass
            if is_empty:
                if seen_empty:
                    changed = True
                    continue
                seen_empty = True
            cleaned.append(value)

        if changed:
            print("PhishingGuard V2 compatibility: removed duplicate empty vocabulary token.")
            vocabulary = cleaned

        return _original_set_vocabulary(self, vocabulary, *args, **kwargs)

    _StringLookup.set_vocabulary = _compat_set_vocabulary
    print("PhishingGuard V2 Keras compatibility shim active.")
except Exception as exc:
    # Do not hide the application's own startup diagnostics if TensorFlow itself
    # cannot be imported; app.py will surface the real failure immediately.
    print(f"PhishingGuard V2 compatibility shim could not initialise: {exc}")

# Deployment marker: clean V2 compatibility rollout.
