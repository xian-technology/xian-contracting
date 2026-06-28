c = __Contract()

@export
def set_c():
    code = '''
@export
def a():
    return 'gottem'
'''
    c.submit(name='baloney', code=code, author='sys')
