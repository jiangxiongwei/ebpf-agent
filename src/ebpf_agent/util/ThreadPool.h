#pragma once
#include<iostream>
#include<queue>
#include <mutex>
#include <thread>
#include <condition_variable>

using namespace  std;
// 定义任务结构体
using callback = void(*)(void*);
struct Task
{
	Task()
	{
		func = nullptr;
		arg = nullptr;
	}
	Task(callback f, void* arg)
	{
		func = f;
		this->arg = arg;
	}
	callback func;
	void* arg;
};
 
// 任务队列
class TaskQueue
{
public:
	TaskQueue();
	~TaskQueue();
 
	// 添加任务
	void addTask(Task& task);
	void addTask(callback func, void* arg);
 
	// 取出一个任务
	Task takeTask();
 
	// 获取当前队列中任务个数
	inline int taskNumber()
	{
		return m_queue.size();
	}
 
private:
	mutex m_mutex;    //pthread_mutex_t m_mutex;  互斥锁
	std::queue<Task> m_queue;   // 任务队列
};
 
 
class ThreadPool
{
public:
	ThreadPool(int min, int max);
	~ThreadPool();
 
	// 添加任务
	void addTask(Task task);
	// 获取忙线程的个数
	int getBusyNumber();
	// 获取活着的线程个数
	int getAliveNumber();
 
private:
	// 工作的线程的任务函数
	static void* worker(void* arg);
	// 管理者线程的任务函数
	static void* manager(void* arg);
	void threadExit();
 
private:
	mutex m_lock; //pthread_mutex_t m_lock;
	condition_variable m_notEmpty; // pthread_cond_t m_notEmpty;
	thread* m_threadIDs; //	pthread_t* m_threadIDs;
	thread m_managerID; //pthread_t m_managerID;
	TaskQueue* m_taskQ;
	int m_minNum;
	int m_maxNum;
	int m_busyNum;
	int m_aliveNum;
	int m_exitNum;
	bool m_shutdown = false;
};
 

