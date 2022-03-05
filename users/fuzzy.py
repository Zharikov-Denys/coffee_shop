from factory.fuzzy import BaseFuzzyAttribute
import random


class FuzzyPhoneNumber(BaseFuzzyAttribute):
    def fuzz(self) -> str:
        return '+' + ''.join([str(random.randint(0, 9)) for i in range(12)])
