from concurrent.futures import ThreadPoolExecutor

class ThreadPoolManager:
    """Manage thread pools for concurrent operations"""

    def __init__(self, max_workers=10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def submit_task(self, func, *args, **kwargs):
        """Submit a task to the thread pool"""
        return self.executor.submit(func, *args, **kwargs)

    def shutdown(self):
        """Clean shutdown of thread pool"""
        self.executor.shutdown(wait=False)
