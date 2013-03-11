Signaturize
===========

A simple class to simplify private/public-key-based
authentication.

Usage:

```
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
```

Client-Side
-----------

```
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
```

Server-Side
-----------

```
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
```
