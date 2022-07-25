"""
Oracles for chosen-ciphertext attacks on PKCS #1
"""
from Crypto.Cipher import PKCS1_v1_5
import multiprocessing
import itertools

def _worker_main(arg):
    addr, port, query_queue, result_queue = arg
    oracle = MbedTLS_Oracle(addr=addr, port=port)
    while True:
        # Read a query from the queue.
        query, args, kwargs = query_queue.get(True)
        
        # Write to the result queue.
        result_queue.put(, block=True)



class MbedTLS_Oracle:
    def __init__(self, addr, port, num_processes):
        self.num_processes = num_processes
        self.pool = multiprocessing.Pool(processes=num_servers)
        self.manager = multiprocessing.Manager()
        self.query_queue = self.manager.Queue()
        self.result_queue = self.manager.Queue()
        worker_arg = (addr, port, self.query_queue, self.result_queue)
        # Create <num_processes> workers that run _worker_main.
        self.pool.map_async(_worker_main, itertools.repeat(worker_arg, num_processes))

    def add_query(self, query, *args, **kwargs):
        
        # Add a query to query_queue; the query object can be anything you like.
        self.query_queue.put((query, args, kwargs), False)
        

    def wait_query(self):

        # Read a query from result_queue (may block until a query is ready)
        result = self.result_queue.get(True)


    def __len__(self):
        return self.num_servers
