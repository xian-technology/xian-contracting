counter = Variable()


@construct
def seed():
    counter.set(0)


@export
def get():
    return counter.get()


@export
def increment():
    counter.set(counter.get() + 1)
    return counter.get()
