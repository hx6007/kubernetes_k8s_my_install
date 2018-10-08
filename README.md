

1、在Master01上必须要和其他服务器ssh互连

   cd /root/.ssh/

   ssh-copy-id -i id_rsa.pub root@192.168.224.182

   ssh-copy-id -i id_rsa.pub root@192.168.224.183

   ssh-copy-id -i id_rsa.pub root@192.168.224.184

   ssh-copy-id -i id_rsa.pub root@192.168.224.185
   
.


2、在Node1上建立与其他服务器的ssh互连

   cd /root/.ssh/

   ssh-copy-id -i id_rsa.pub root@192.168.224.181

   ssh-copy-id -i id_rsa.pub root@192.168.224.182

   ssh-copy-id -i id_rsa.pub root@192.168.224.184

   ssh-copy-id -i id_rsa.pub root@192.168.224.185
   
  
. 
.

  
.




3、所有都创建目录

 mkdir -pv /etc/kubernetes/ssl/

 mkdir -pv /usr/k8s/bin/

 mkdir -pv ~/.kube/

 mkdir -pv /etc/flanneld/ssl

 mkdir /data/k8s/kubedns -pv
  
.
 

 Master01 和 Node1 安装lrzsz

yum -y install lrzsz

.

4、Master01上，将本地电脑的kubernetes-server-linux-amd64.tar.gz上传

 cd /usr/local/src

 rz -E

 tar xvf  kubernetes-server-linux-amd64.tar.gz 

cp -v kubernetes/server/bin/{kubeadm,kube-apiserver,kube-controller-manager,kubectl,kubelet,kube-proxy,kube-scheduler} /usr/k8s/bin/


 scp /usr/k8s/bin/kubectl root@192.168.224.182:/usr/k8s/bin/

 scp /usr/k8s/bin/kubectl root@192.168.224.183:/usr/k8s/bin/

 scp /usr/k8s/bin/kubectl root@192.168.224.184:/usr/k8s/bin/

 scp /usr/k8s/bin/kubectl root@192.168.224.185:/usr/k8s/bin/

 scp -rv kubernetes/server/bin/{kube-apiserver,kube-controller-manager,kube-scheduler} root@192.168.224.182:/usr/k8s/bin/


scp -rv kubernetes/server/bin/{kube-proxy,kubelet} root@192.168.224.183:/usr/k8s/bin/

scp -rv kubernetes/server/bin/{kube-proxy,kubelet} root@192.168.224.184:/usr/k8s/bin/

scp -rv kubernetes/server/bin/{kube-proxy,kubelet} root@192.168.224.185:/usr/k8s/bin/

  

.

  
.




5、Master01上，将本地电脑的  etcd-v3.3.9-linux-amd64.tar.gz 上传

 cd /usr/local/src

 rz -E

  tar xvf etcd-v3.3.9-linux-amd64.tar.gz

 sudo cp -v etcd-v3.3.9-linux-amd64/etcd* /usr/k8s/bin/

 scp etcd-v3.3.9-linux-amd64/etcd* root@192.168.224.182:/usr/k8s/bin/

 scp etcd-v3.3.9-linux-amd64/etcd* root@192.168.224.183:/usr/k8s/bin/

 scp etcd-v3.3.9-linux-amd64/etcd* root@192.168.224.184:/usr/k8s/bin/

 scp etcd-v3.3.9-linux-amd64/etcd* root@192.168.224.185:/usr/k8s/bin/

  
.
 
.

  
.




6、Master01上，将本地电脑的 cfssl_linux-amd64  cfssl-certinfo_linux-amd64  cfssljson_linux-amd64 上传


 chmod +x cfssl_linux-amd64
 
 sudo mv cfssl_linux-amd64 /usr/k8s/bin/cfssl
 
 chmod +x cfssljson_linux-amd64
 
 sudo mv cfssljson_linux-amd64 /usr/k8s/bin/cfssljson

 chmod +x cfssl-certinfo_linux-amd64
 
 sudo mv cfssl-certinfo_linux-amd64 /usr/k8s/bin/cfssl-certinfo
 
 
scp  /usr/k8s/bin/{cfssl,cfssljson,cfssl-certinfo} root@192.168.224.182:/usr/k8s/bin/

scp  /usr/k8s/bin/{cfssl,cfssljson,cfssl-certinfo} root@192.168.224.183:/usr/k8s/bin/

scp  /usr/k8s/bin/{cfssl,cfssljson,cfssl-certinfo} root@192.168.224.184:/usr/k8s/bin/

scp  /usr/k8s/bin/{cfssl,cfssljson,cfssl-certinfo} root@192.168.224.185:/usr/k8s/bin/


  
.

  
.
 
.

  
.





7、Node01上，将本地电脑的flannel-v0.10.0-linux-amd64.tar.gz上传到

 cd /usr/local/src && mkdir flannel

 rz -E

 tar xvf flannel-v0.10.0-linux-amd64.tar.gz -C flannel

 sudo cp flannel/{flanneld,mk-docker-opts.sh} /usr/k8s/bin
 

 scp flannel/{flanneld,mk-docker-opts.sh} root@192.168.224.184:/usr/k8s/bin

 scp flannel/{flanneld,mk-docker-opts.sh} root@192.168.224.185:/usr/k8s/bin

  
.

  
.



8其他：


8.7、验证 master 节点

$ kubectl get componentstatuses


然后我们可以通过上面9000端口监控我们的haproxy的运行状态(192.168.224.181:9000/stats):

  
.

  
.


# 查看日志
journalctl -f -u keepalived

  
.

  
.


验证虚拟IP

在 Master01 节点上执行操作

# 使用ifconfig -a 命令查看不到，要使用ip addr

[root@k8s-master01 keepalived]# ip addr

 
.

  
.


验证集群状态

[root@k8s-master01 ~]# kubectl get cs

停止Master01 节点的 kube-apiserver 服务

$ systemctl stop kube-apiserver

验证 VIP 是否在Master02节点，获取集群状态信息

[root@k8s-master02 ~]# ip a|grep 186

[root@k8s-master02 ~]# kubectl get cs


 
.

  
.



每台node节点检查文件系统的类型，默认docker的存储驱动是 devicemaper 如果要使用overlay2 需要 xfs 文件系统的 ftype=1 才可以使用，如果不是，参考总教程：https://github.com/hx6007/Kubernetes-my-study/blob/master/install_ok(2master%2B3node)

检查命令如下：

 xfs_info /var/

 
.

  
.



检查 docker0 网卡是否与 flannel.1 网卡在同一网络

 ifconfig flannel.1

 ifconfig docker0



 
.

  
.



9.6、通过 kubelet 的 TLS 证书请求

kubelet 首次启动时向kube-apiserver 发送证书签名请求，必须通过后kubernetes 系统才会将该 Node 加入到集群。查看未授权的CSR 请求：

在 Master01 节点上操作

kubectl get csr

 kubectl get nodes


No resources found.

通过CSR 请求：

for i in `kubectl get csr|awk '{print $1}'|grep -v "NAME"`;do kubectl certificate approve $i;done

 
.

  
.


# 查看 Node 节点

[root@k8s-master01 ~]# kubectl get nodes

NAME           STATUS    ROLES     AGE       VERSION

192.168.224.183   Ready     <none>    2m        v1.9.7

192.168.224.184   Ready     <none>    39s       v1.9.7

192.168.224.185   Ready     <none>    2m        v1.9.7


 
.

  
.


master01上

执行下面的命令查看Pod 和SVC：

[root@k8s-master01 pod]# kubectl get pods -o wide

NAME             READY     STATUS    RESTARTS   AGE       IP            NODE

nginx-ds-hzqm2   1/1       Running   0          2m        172.30.40.2   192.168.224.183

nginx-ds-jhhgb   1/1       Running   0          2m        172.30.43.2   192.168.224.185

nginx-ds-xf5qq   1/1       Running   0          2m        172.30.24.2   192.168.224.184

[root@k8s-master01 pod]# kubectl get svc

NAME         TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE

kubernetes   ClusterIP   10.254.0.1       <none>        443/TCP        2h

nginx-ds     NodePort    10.254.136.253   <none>        80:32766/TCP   3m


 
.

  
.


在所有 Node 上执行：

curl  10.254.136.253

curl 192.168.224.183:32766


[root@k8s-master01 pod]# kubectl get svc


[root@k8s-master01 pod] kubectl exec  nginx -i -t -- /bin/bash


root@nginx:/# cat /etc/resolv.conf

nameserver 10.254.0.2

search default.svc.cluster.local. svc.cluster.local. cluster.local.

options ndots:5


 
.

  
.




root@nginx:/# ping my-nginx

PING my-nginx.default.svc.cluster.local (10.254.51.165): 48 data bytes
^C--- my-nginx.default.svc.cluster.local ping statistics ---
2 packets transmitted, 0 packets received, 100% packet loss
root@nginx:/# ping kubernetes
PING kubernetes.default.svc.cluster.local (10.254.0.1): 48 data bytes
^C--- kubernetes.default.svc.cluster.local ping statistics ---
2 packets transmitted, 0 packets received, 100% packet loss




 
.

  
.




检查执行结果

查看分配的 NodePort

$ kubectl get services kubernetes-dashboard -n kube-system

NAME                   TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
kubernetes-dashboard   NodePort   10.254.204.176   <none>        80:32092/TCP   49s


•	NodePort 32092 映射到dashboard pod 80端口；

检查 controller

$ kubectl get deployment kubernetes-dashboard  -n kube-system

NAME                   DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE

kubernetes-dashboard   1         1         1            1           1m


$ kubectl get pods  -n kube-system | grep dashboard

kubernetes-dashboard-85f875c69c-mbljw   1/1       Running   0          2m


访问dashboard

kubernetes-dashboard 服务暴露了 NodePort，可以使用 http://NodeIP:nodePort 地址访问 dashboard，例如：http://192.168.224.184:23495

由于缺少 Heapster 插件，当前 dashboard 不能展示 Pod、Nodes 的 CPU、内存等 metric 图形。


 
.

  
.



检查执行结果

检查 Deployment

$ kubectl get deployments -n kube-system | grep -E 'heapster|monitoring'

heapster               1         1         1            1           29m

monitoring-grafana     1         1         1            1           29m

monitoring-influxdb    1         1         1            1           29m

检查 Pods
$ kubectl get pods -n kube-system | grep -E 'heapster|monitoring'

heapster-9bd589759-nz29g                1/1       Running   0          30m

monitoring-grafana-5c8d68cb94-xtszf     1/1       Running   0          30m

monitoring-influxdb-774cf8fcc6-b7qw7    1/1       Running   0          30m

访问 grafana

上面我们修改grafana 的Service 为NodePort 类型：

[root@k8s-master01 kube-config]# kubectl get svc -n kube-system

NAME                   TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)         AGE

heapster               ClusterIP   10.254.170.2     <none>        80/TCP          30m

kube-dns               ClusterIP   10.254.0.2       <none>        53/UDP,53/TCP   1h

kubernetes-dashboard   NodePort    10.254.204.176   <none>        80:32092/TCP    48m

monitoring-grafana     NodePort    10.254.112.219   <none>        80:30879/TCP    30m

monitoring-influxdb    ClusterIP   10.254.109.148   <none>        8086/TCP        30m


则我们就可以通过任意一个节点加上上面的30879端口就可以访问grafana 了。




$ kubectl get pods -n ingress-nginx -o wide

NAME                                        READY     STATUS    RESTARTS   AGE       IP             NODE

default-http-backend-7ddd8d57f4-dtvgd       1/1       Running   0          7m        172.30.43.4    192.168.224.185

nginx-ingress-controller-7494c4c66d-9r6j5   1/1       Running   0          7m        192.168.224.184   192.168.224.184




在本地电脑添加一条hosts test.nginxds.com 解析到 nginx-ingress-controlle 所在 的Node 节点的IP上，通过kubectl get pods -n ingress-nginx -o wide可以获取IP

192.168.224.184 test.nginxds.com

修改 nginx 容器的默认首页

在浏览器上访问 test.nginxds.com 测试







