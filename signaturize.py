from collections import OrderedDict
import hashlib
import hmac
import time


class SignaturizeException(Exception):
    pass


class Signaturize(object):
    """A simple class to simplify private/public-key-based
    authentication.

    Usage:

    from signaturize import Signaturize

    sig = Signaturize("PUBLIC_KEY", "PRIVATE_KEY",
                    first_name="Jesse",
                    last_name="Panganiban",
                    age=21,
                    location="Quezon City",
                    country="Philippines")

    sig.signature  # Returns the hashed value of data
                    # with the timestamp.

    sig.to_dict()  # Returns a dictionary containing
                    # the values

    Client-Side
    -----------

    import requests

    person = {
        "name": "Juan Dela Cruz",
        "age": 25,
        "location": "Philippines"
    }

    sig = Signaturize("PUBLIKO_KEY", "SIKRETO_KEY",
                      **person)

    requests.get("http://awesomeservice.com",
                 data=sig.to_dict(include_public_key=False,
                                  include_timestamp=False),
                 headers={"X-Service-Public-Key": sig.public_key,
                          "X-Service-Timestamp": sig.timestamp,
                          "X-Service-Signature": sig.signature})

    or

    requests.get("http://awesomeservice.com",
                 data=sig.to_dict())

    Server-Side
    -----------

    # Public Key and Timestamp in headers
    request_public_key = request.headers.get("X-Service-Public-Key")
    timestamp = request.headers.get("X-Service-Timestamp")
    request_signature = request.headers.get("X-Service-Signature")

    # Expire signatures every 30 minutes
    if (timestamp - int(time.time())) > 60 * 30:
        abort(401, "Request not authorized")

    # Query consumer from the database..
    consumer = Consumer.filter_by(public_key=request_public_key).first()
    sig = Signaturize(request_public_key, consumer.private_key,
                      **request.data)

    # Check if the signature matches
    if sig.signature != request_signature:
        abort(401, "Request not authorized")

    # Request Granted. Yay!
    """

    def __init__(self, public_key, private_key, **data):
        self.public_key = public_key
        self.private_key = private_key

        if "timestamp" in data:
            data.pop("timestamp")
        if "public_key" in data:
            data.pop("public_key")
        if "signature" in data:
            data.pop("signature")

        self._data = data
        self.timestamp = int(time.time())

    def set_data(self, key, value):
        """Data setter"""
        self._data[key] = value

    def get_data(self, key):
        """Data getter"""
        return self._data.get(key, None)

    def del_data(self, key):
        """Remove key from data"""
        if key in self._data:
            del self._data[key]

    @property
    def sorted_data(self):
        """Sort the data applied by its key"""
        return OrderedDict(sorted(self._data.items()))

    @property
    def data_string(self):
        """Creates a string representation of the data"""

        # Generate hash string. It's a lot simpler to do
        # this instead of updating the hash object multiple
        # times. It's a lot safer as well.
        data_string = ""
        for key, value in self.sorted_data.iteritems():
            data_string += "%s:%s-" % (key, value)

        # Add the timestamp at the end of the data_string.
        data_string += "timestamp:%s" % self.timestamp

        return data_string

    @property
    def signature(self):
        """Generates the signature for the object."""

        # Create the the hash object. Apply the private_key
        # as the key and the data_string as the data.
        h = hmac.HMAC(self.private_key, self.data_string, hashlib.sha1)

        # Finally, produce the hex string
        return h.hexdigest()

    def to_dict(self, include_public_key=True,
                include_timestamp=True,
                include_signature=True):
        """Convinience method for creating a dict of all
        the data usually needed for a request."""
        d = dict(self.sorted_data)
        if include_timestamp:
            d["timestamp"] = self.timestamp
        if include_public_key:
            d["public_key"] = self.public_key
        if include_signature:
            d["signature"] = self.signature
        return d
