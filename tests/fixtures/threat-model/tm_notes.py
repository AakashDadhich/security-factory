from pytm import TM, Actor, Boundary, Classification, Data, Dataflow, Datastore, Server

tm = TM("Notes app")
tm.description = "Signed-in users keep private text notes."
tm.isOrdered = True

internet = Boundary("Internet")
server_zone = Boundary("Server")

user = Actor("User", inBoundary=internet)
web = Server("Web app", inBoundary=server_zone)
web.protocol = "HTTPS"
web.controls.sanitizesInput = True
db = Datastore("Notes DB", inBoundary=server_zone)
db.storesPII = True

note = Data("Note text", classification=Classification.SENSITIVE)

sign_in = Dataflow(user, web, "Sign-in request")
sign_in.protocol = "HTTPS"
sign_in.dstPort = 443
create = Dataflow(user, web, "Create note request", data=[note])
create.protocol = "HTTPS"
store = Dataflow(web, db, "Store note")
store.protocol = "SQL"
read = Dataflow(db, web, "Read notes")
read.protocol = "SQL"
reply = Dataflow(web, user, "Notes response", data=[note])
reply.protocol = "HTTPS"

if __name__ == "__main__":
    tm.process()
