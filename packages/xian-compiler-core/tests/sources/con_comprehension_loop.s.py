@export
def summarize(values: list[int]) -> dict:
    total = 0
    result = [value for value in values if value > 0]
    while total < len(result):
        total += 1
    return {str(value): value * 2 for value in result}
