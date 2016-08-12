import threading

def print_statement(str):
	print str

class MyThread(threading.Thread):
	def __init__(self, statement):
		threading.Thread.__init__(self)
		self.statement =  statement

	def run(self):
		print_statement(self.statement)

thread1 = MyThread("hello")
thread2= MyThread("bye")
thread3 = MyThread("goodnight")

lock = thraeding.Lock()



