"""
Oracles for chosen-ciphertext attacks on PKCS #1

This script uses the oracle from oracles.py (here called MbedTLS_Oracle_Single) and implements a new
    oracle class (MbedTLS_Oracle) that allows parallelization of queries.
Missing parts that need to be completed are marked by ## ??? ##.
"""
from oracles import MbedTLS_Oracle as MbedTLS_Oracle_Single
import multiprocessing
import itertools

def _worker_main(arg):
    """
    This is a "worker" function that receives parallelized queries from the query queue,
        handles them (runs the query), and writes their results to the result queue.
    :param arg: argument tuple:
        :param addr: the server's address.
        :param port: the server's port.
        :param query_queue: the query queue to read queries from.
        :param result_queue: the result queue to write responses to.
    """
    addr, port, query_queue, result_queue = arg
    oracle = MbedTLS_Oracle_Single(addr=addr, port=port)  # Initialize a single oracle connection
    while True:
        # Read a query from the queue.
        query, args, kwargs = query_queue.get(True)
        
        ## ??? ##
        result = None ## ??? ##

        # Write to the result queue.
        result_queue.put(result, block=True)


class MbedTLS_Oracle:
    def __init__(self, addr, port, num_processes):
        """
        Initialize a parallelized oracle.
        :param addr: the server's address.
        :param port: the server's port.
        :param num_processes: the number of worker processes to create.
        """
        self.num_processes = num_processes
        self.pool = multiprocessing.Pool(processes=num_servers)
        self.manager = multiprocessing.Manager()
        self.query_queue = self.manager.Queue()  # Queue to send queries on
        self.result_queue = self.manager.Queue()  # Queue to receive responses from
        worker_arg = (addr, port, self.query_queue, self.result_queue)
        # Create <num_processes> worker processes that run _worker_main.
        self.pool.map_async(_worker_main, itertools.repeat(worker_arg, num_processes))

    def add_query(self, query, *args, **kwargs):
        """
        Add a query to the query queue, to be handled by a worker process.
        :param query: the query object to send; can be any object as long as _worker_main handles it.
        :param args: additional arguments are passed as a tuple in the queue.
        :param kwargs: addition keywords arguments are passed as a dictionary in the queue.
        """
        # Add a query to query_queue; the query object can be anything you like.
        self.query_queue.put((query, args, kwargs), False)
        
    def wait_query(self):
        """
        Read a query from the result queue. May block until a query is ready.
        Responses may not return in order; the first response to be pushed to the queue by a worker
            process is the first that will be returned, regardless of the order of the respective queries.
        """
        # Read a query from result_queue (may block until a query is ready)
        result = self.result_queue.get(True)

    def __len__(self):
        """
        The length of an instance of this class is the number of worker processes.
        """
        return self.num_servers
