
## 自动收集信息尝试Exploit
设计：  
1. (done) 持续收集外面的进程名称  
2. (done) openoose， execnoose  
3. 选出可攻击的进程，重点观察  
4. 找出更多可利用的系统调用  


### TODO

#### 1. (done) ringbuffer 持续收集log
使用自带的ringbuffer有问题。因此使用一个map来模拟ringbuffer。

#### 2. (done) execvsnoop 和 opensnoop


#### 3. 关键进程的trace
https://filippo.io/linux-syscall-table/

```
2022/07/11 15:37:42 [LOG] trace: dockerd 202
2022/07/11 15:37:42 [LOG] trace: dockerd 281
2022/07/11 15:37:42 [LOG] trace: dockerd 202
2022/07/11 15:37:42 [LOG] trace: dockerd 281
2022/07/11 15:37:42 [LOG] trace: dockerd 202
2022/07/11 15:37:42 [LOG] trace: dockerd 35
```
