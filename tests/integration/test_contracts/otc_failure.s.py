reentrancy = Variable(default_value=False)
otc_listing = Hash()

@construct
def seed():
    otc_listing['listing'] = {'status': 'OPEN'}

@export
def get_listing():
    return otc_listing['listing']

@export
def guard_active():
    return reentrancy.get()

@export
def take():
    assert not reentrancy.get(), 'Contract is busy'
    reentrancy.set(True)

    listing = otc_listing['listing']
    assert listing is not None, 'Missing listing'
    assert listing['status'] == 'OPEN', 'Offer not available'

    listing['status'] = 'EXECUTED'
    otc_listing['listing'] = listing

    assert False, 'Not enough coins to send.'
