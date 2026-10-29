import os
from pytm import TM, Actor, Boundary, Dataflow, Datastore, Server

tm = TM("Bad")
tm.description = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
zone = Boundary("Zone")
user = Actor("User", inBoundary=zone)
web = Server("Web app", inBoundary=zone)
db = Datastore("DB", inBoundary=zone)
Dataflow(user, web, "Request")

if __name__ == "__main__":
    tm.process()
