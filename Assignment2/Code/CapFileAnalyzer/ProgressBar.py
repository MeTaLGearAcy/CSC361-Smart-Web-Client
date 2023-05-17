import time


class ProgressBar:
    __max_len = 0
    __start_time = None
    __now_count = 0
    __scale = 50
    __finish = False
    __speed = 0

    def __init__(self, max_len, scale=50):
        self.__max_len = max_len
        self.__start_time = time.perf_counter()
        self.__scale = scale

    def next(self, add_num=1):
        if self.__finish:
            raise EOFError("End of progress bar but continue looping.")
        self.__now_count += add_num
        if self.__now_count >= self.__max_len:
            self.finish()
        else:
            __progress = self.__now_count / self.__max_len
            __left = self.__max_len - self.__now_count
            __used_time = time.perf_counter() - self.__start_time
            self.__speed = self.__now_count / __used_time
            print("\r{:^3.0f}%[{}->{}] {}/{} {:.2f}s->{:.2f}s, {:.2f}it/s".format((__progress * 100),
                                                                                  "#" * int(__progress * self.__scale),
                                                                                  "." * (self.__scale - int(
                                                                                      __progress * self.__scale)),
                                                                                  self.__now_count,
                                                                                  self.__max_len,
                                                                                  __used_time,
                                                                                  __left / self.__speed,
                                                                                  self.__speed), end="", flush=True)

    def finish(self):
        self.__finish = True
        print("\r{:^3.0f}%[{}] {}/{} {:.2f}s, {:.2f}it/s\n".format(100, "#" * (self.__scale + 2),
                                                                   self.__max_len,
                                                                   self.__max_len,
                                                                   time.perf_counter() - self.__start_time,
                                                                   self.__speed), end="", flush=True)

    def get_now_count(self):
        return self.__now_count
