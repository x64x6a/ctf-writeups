"""
th4t_was_be4rly_a_chall3nge@flare-on.com
"""

# used jadx to decompile to source


class Tamagotchi(object):
    def __init__(self):
        self.p = 0.0
        self.f = 0.0
        self.c = 0.0

        self._happy = 0
        self._mass = 0
        self._clean = 0

    def __str__(self):
        if self.p != 0.0:
            res = self.f / self.p
        else:
            res = "{}/{}".format(self.f, self.p)
        return r"""    (f/p) -> {}
    mass  = {}  (72)
    happy = {}  (30)
    clean = {}  (0)

    isHappy() -> {}
    isEcstatic() -> {}
""".format(res, self._mass, self._happy, self._clean, self.isHappy(), self.isEcstatic())

    def isHappy(self):
        if self.p == 0.0:
            return "ZeroDivisionError"
        v = self.f / self.p
        return 2.0 <= v and v <= 2.5

    def isEcstatic(self):
        return self._mass == 72 and self._happy == 30 and self._clean == 0

    def feed(self):
        self.f += 1.0

        self._mass += 10
        self._happy += 2
        self._clean += -1

    def play(self):
        self.p += 1.0

        self._mass += -2
        self._happy += 4
        self._clean += -1

    def clean(self):
        self.c += 1.0

        self._mass += 0
        self._happy += -1
        self._clean += 6


flarebear = Tamagotchi()

for i in range(4):
    flarebear.feed()
    flarebear.feed()
    flarebear.play()
for i in range(2):
    flarebear.clean()

print flarebear
