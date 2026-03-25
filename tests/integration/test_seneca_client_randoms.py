from unittest import TestCase
from contracting.client import ContractingClient

def con_random_contract():
    random.seed()

    cards = [1, 2, 3, 4, 5, 6, 7, 8]

    cardinal_values = ['A', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']
    suits = ['S', 'C', 'H', 'D']

    cities = ['Cleveland', 'Detroit', 'Chicago', 'New York', 'San Francisco']

    @export
    def shuffle_cards(**kwargs: dict):
        random.shuffle(cards)
        return cards

    @export
    def random_number(k: int):
        return random.randrange(k)

    @export
    def random_number_2(k: int):
        # adjust the random state by calling another random function
        shuffle_cards()
        return random.randrange(k)

    @export
    def random_bits(k: int):
        shuffle_cards()
        shuffle_cards()
        shuffle_cards()
        return random.getrandbits(k)

    @export
    def int_in_range(a: int, b: int):
        shuffle_cards()
        shuffle_cards()
        return random.randint(a, b)

    @export
    def deal_card():
        random.shuffle(cardinal_values)
        random.shuffle(cardinal_values)
        random.shuffle(cardinal_values)

        random.shuffle(suits)
        random.shuffle(suits)
        random.shuffle(suits)

        c = ''
        c += random.choice(cardinal_values)
        c += random.choice(suits)

        return c

    @export
    def pick_cities(k: int):
        return random.choices(cities, k)

    @export
    def shuffle_cards_salted(salt: str):
        random.seed(salt)
        salted_cards = [1, 2, 3, 4, 5, 6, 7, 8]
        random.shuffle(salted_cards)
        return salted_cards


class TestRandomsContract(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer='stu')
        self.c.flush()
        self.c.submit(con_random_contract)

        self.random_contract = self.c.get_contract('con_random_contract')

    def tearDown(self):
        self.c.flush()

    def test_basic_shuffle(self):
        cards_1 = self.random_contract.shuffle_cards()
        cards_2 = self.random_contract.shuffle_cards()

        self.assertEqual(cards_1, cards_2)

    def test_basic_shuffle_different_with_different_seeds(self):
        cards_1 = self.random_contract.shuffle_cards(environment={'block_num': 999})
        cards_2 = self.random_contract.shuffle_cards(environment={'block_num': 998})

        self.assertNotEqual(cards_1, cards_2)

    def test_random_num_one_vs_two(self):
        k = self.random_contract.random_number(k=1000)
        k2 = self.random_contract.random_number_2(k=1000)

        self.assertNotEqual(k, k2)

    def test_random_getrandbits_is_deterministic_for_same_environment(self):
        first = self.random_contract.random_bits(k=20)
        second = self.random_contract.random_bits(k=20)

        self.assertEqual(first, second)

    def test_random_range_int(self):
        a = self.random_contract.int_in_range(a=100, b=50000)
        b = self.random_contract.int_in_range(a=100, b=50000)

        self.assertEqual(a, b)
        self.assertGreaterEqual(a, 100)
        self.assertLessEqual(a, 50000)

    def test_random_choice(self):
        first = self.random_contract.pick_cities(k=2)
        second = self.random_contract.pick_cities(k=2)

        self.assertListEqual(first, second)
        self.assertEqual(len(first), 2)

    def test_literal_seed_salt_changes_sequence(self):
        cards_1 = self.random_contract.shuffle_cards_salted(salt="round-a")
        cards_2 = self.random_contract.shuffle_cards_salted(salt="round-a")
        cards_3 = self.random_contract.shuffle_cards_salted(salt="round-b")

        self.assertEqual(cards_1, cards_2)
        self.assertNotEqual(cards_1, cards_3)
