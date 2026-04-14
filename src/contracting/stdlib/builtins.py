def eager_map(function, *iterables):
    if function is None or not callable(function):
        raise TypeError("map() must have a callable first argument")
    if len(iterables) == 0:
        raise TypeError("map() must have at least two arguments")
    return [function(*items) for items in zip(*iterables)]


def eager_filter(function, iterable):
    if function is None:
        return [item for item in iterable if item]
    if not callable(function):
        raise TypeError("filter() must have a callable first argument or None")
    return [item for item in iterable if function(item)]


exports = {"map": eager_map, "filter": eager_filter}
