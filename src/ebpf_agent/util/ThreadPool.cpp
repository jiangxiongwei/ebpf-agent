#include "ThreadPool.h"
#include <string>
#include<functional>
#include<sstream>
#include <string.h>


TaskQueue::TaskQueue()
{
	//pthread_mutex_init(&m_mutex, NULL);
}
 
TaskQueue::~TaskQueue()
{
	// pthread_mutex_destroy(&m_mutex);
}
 
void TaskQueue::addTask(Task& task)
{
 
	m_mutex.lock();  //pthread_mutex_lock(&m_mutex);
	m_queue.push(task);
	m_mutex.unlock(); //pthread_mutex_unlock(&m_mutex);
}
 
void TaskQueue::addTask(callback func, void* arg)
{
	m_mutex.lock(); //pthread_mutex_lock(&m_mutex);
	Task task;
	task.func = func;
	task.arg = arg;
	m_queue.push(task);
	m_mutex.unlock();//pthread_mutex_unlock(&m_mutex);
}
 
Task TaskQueue::takeTask()
{
	Task t;
	m_mutex.lock();//pthread_mutex_lock(&m_mutex);
	if (m_queue.size() > 0)
	{
		t = m_queue.front();
		m_queue.pop();
	}
	m_mutex.unlock();//pthread_mutex_unlock(&m_mutex);
	return t;
}
 
ThreadPool::ThreadPool(int minNum, int maxNum)
{
	// 实例化任务队列
	m_taskQ = new TaskQueue;
	do {
		// 初始化线程池
		m_minNum = minNum;
		m_maxNum = maxNum;
		m_busyNum = 0;
		m_aliveNum = minNum;
 
		// 根据线程的最大上限给线程数组分配内存
		m_threadIDs = new thread[maxNum];//new pthread_t[maxNum];
		if (m_threadIDs == nullptr)
		{
			cout << "malloc thread_t[] failed...." << endl;;
			break;
		}
		// 初始化
		memset(m_threadIDs, 0, sizeof(thread) * maxNum);
		
		/// 创建线程 //
		// 根据最小线程个数, 创建线程
		for (int i = 0; i < minNum; ++i)
		{
			m_threadIDs[i] = thread(std::bind(&ThreadPool::worker,this));
			
			cout << "创建子线程, ID: " << m_threadIDs[i].get_id() << endl;
		}
		// 创建管理者线程, 1个
		m_managerID = thread(std::bind(&ThreadPool::manager, this));
	} while (0);
}
 
ThreadPool::~ThreadPool()
{
	m_shutdown = 1;
	// 销毁管理者线程
	m_managerID.join();
	for (int i = 0; i < m_aliveNum; ++i)
	{
		m_notEmpty.notify_one(); //pthread_cond_signal(&m_notEmpty);
	}
 
	if (m_taskQ) delete m_taskQ;
	if (m_threadIDs) delete[]m_threadIDs;
}
 
void ThreadPool::addTask(Task task)
{
	if (m_shutdown)
	{
		return;
	}
	// 添加任务，不需要加锁，任务队列中有锁
	m_taskQ->addTask(task);
	// 唤醒工作的线程
	m_notEmpty.notify_one();//pthread_cond_signal(&m_notEmpty);
}
 
int ThreadPool::getAliveNumber()
{
	int threadNum = 0;
	m_lock.lock();
	threadNum = m_aliveNum;
	m_lock.unlock();
	return threadNum;
}
 
int ThreadPool::getBusyNumber()
{
	int busyNum = 0;
	m_lock.lock();
	busyNum = m_busyNum;
	m_lock.unlock();
	return busyNum;
}
 
 
// 工作线程任务函数
void* ThreadPool::worker(void* arg)
{
	ThreadPool* pool = static_cast<ThreadPool*>(arg);
	// 一直不停的工作
	while (true)
	{
		// 访问任务队列(共享资源)加锁
		pool->m_lock.lock();
		// 判断任务队列是否为空, 如果为空工作线程阻塞
		while (pool->m_taskQ->taskNumber() == 0 && !pool->m_shutdown)
		{
			cout << "thread " << this_thread::get_id() << " waiting..." << endl;
			// 阻塞线程
			mutex _mut;
			std::unique_lock <std::mutex> lck(_mut); //创建时自动加锁，析构时解锁
			pool->m_notEmpty.wait(lck);
 
			// 解除阻塞之后, 判断是否要销毁线程
			if (pool->m_exitNum > 0)
			{
				pool->m_exitNum--;
				if (pool->m_aliveNum > pool->m_minNum)
				{
					pool->m_aliveNum--;
					pool->m_lock.unlock();
					pool->threadExit();
					return nullptr;
				}
			}
		}
		// 判断线程池是否被关闭了
		if (pool->m_shutdown)
		{
			pool->m_lock.unlock();
			pool->threadExit();
		}
 
		// 从任务队列中取出一个任务
		Task task = pool->m_taskQ->takeTask();
		// 工作的线程+1
		pool->m_busyNum++;
		// 线程池解锁
		pool->m_lock.unlock();
		// 执行任务
		cout << "thread " << this_thread::get_id() << " start working..." << endl;
		task.func(task.arg);
		delete task.arg;
		task.arg = nullptr;
 
		// 任务处理结束
		cout << "thread " << this_thread::get_id() << " end working...";
		pool->m_lock.lock();
		pool->m_busyNum--;
		pool->m_lock.unlock();
	}
 
	return nullptr;
}
 
 
// 管理者线程任务函数
void* ThreadPool::manager(void* arg)
{
	ThreadPool* pool = static_cast<ThreadPool*>(arg);
	// 如果线程池没有关闭, 就一直检测
	while (!pool->m_shutdown)
	{
		// 每隔5s检测一次
		this_thread::sleep_for(chrono::seconds(5));	// 取出线程池中的任务数和线程数量
		//  取出工作的线程池数量
		pool->m_lock.lock();
		int queueSize = pool->m_taskQ->taskNumber();
		int liveNum = pool->m_aliveNum;
		int busyNum = pool->m_busyNum;
 
		// 创建线程
		const int NUMBER = 2;
		// 当前任务个数>存活的线程数 && 存活的线程数<最大线程个数
		if (queueSize > liveNum && liveNum < pool->m_maxNum)
		{
			// 线程池加锁
			int num = 0;
			for (int i = 0; i < pool->m_maxNum && num < NUMBER
				&& pool->m_aliveNum < pool->m_maxNum; ++i)
			{
				stringstream s;
				s << pool->m_threadIDs[i].get_id();
				if (atol(s.str().c_str()) == 0) //  pool->m_threadIDs[i] == 0
				{
					pool->m_threadIDs[i] = thread(std::bind(&ThreadPool::worker, &pool));
					num++;
					pool->m_aliveNum++;
				}
			}
			pool->m_lock.unlock();
		}
 
		// 销毁多余的线程
		// 忙线程*2 < 存活的线程数目 && 存活的线程数 > 最小线程数量
		if (busyNum * 2 < liveNum && liveNum > pool->m_minNum)
		{
			pool->m_lock.lock();
			pool->m_exitNum = NUMBER;
			pool->m_lock.unlock();
			for (int i = 0; i < NUMBER; ++i)
			{
				pool->m_notEmpty.notify_one();
			}
		}
	}
	return nullptr;
}
 
// 线程退出
void ThreadPool::threadExit()
{
	thread::id tid = this_thread::get_id();
	for (int i = 0; i < m_maxNum; ++i)
	{
		if (m_threadIDs[i].get_id() == tid)
		{
			cout << "threadExit() function: thread "
				<< this_thread::get_id() << " exiting..." << endl;
			memset(&m_threadIDs[i], 0, sizeof(thread));
			break;
		}
	}
 
}

