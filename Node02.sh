#!/bin/bash

sed -i 's/enforcing/disabled/g' /etc/selinux/config
setenforce 0
iptables -F
iptables -t nat -F
iptables -I FORWARD -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT  
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 2379 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 2380 -j ACCEPT


 mkdir -pv /usr/k8s/bin
 cd /usr/k8s/bin
 cat << EOF  >  env.sh
BOOTSTRAP_TOKEN="3da3ebeda2462bce41766a086f8eb9fb"
SERVICE_CIDR="10.254.0.0/16"
CLUSTER_CIDR="172.30.0.0/16"
NODE_PORT_RANGE="20000-40000"
ETCD_ENDPOINTS="https://192.168.224.181:2379,https://192.168.224.182:2379,https://192.168.224.183:2379"
FLANNEL_ETCD_PREFIX="/kubernetes/network"
CLUSTER_KUBERNETES_SVC_IP="10.254.0.1"
CLUSTER_DNS_SVC_IP="10.254.0.2"
CLUSTER_DNS_DOMAIN="cluster.local."
MASTER_URL="k8s-api.virtual.local"
EOF
chmod +x env.sh
echo "192.168.224.181 k8s-api.virtual.local k8s-api" >>  /etc/hosts



 export NODE_IP=192.168.224.185  

source /usr/k8s/bin/env.sh



 cat > flanneld-csr.json << EOF
{
  "CN": "flanneld",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF


 

 export PATH=/usr/k8s/bin:$PATH

 cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem \
  -ca-key=/etc/kubernetes/ssl/ca-key.pem \
  -config=/etc/kubernetes/ssl/ca-config.json \
  -profile=kubernetes flanneld-csr.json | cfssljson -bare flanneld

 sudo mv flanneld*.pem /etc/flanneld/ssl




cat > flanneld.service << EOF
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
ExecStart=/usr/k8s/bin/flanneld \\
  -etcd-cafile=/etc/kubernetes/ssl/ca.pem \\
  -etcd-certfile=/etc/flanneld/ssl/flanneld.pem \\
  -etcd-keyfile=/etc/flanneld/ssl/flanneld-key.pem \\
  -etcd-endpoints=${ETCD_ENDPOINTS} \\
  -etcd-prefix=${FLANNEL_ETCD_PREFIX}
ExecStartPost=/usr/k8s/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF



cp -v flanneld.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable flanneld
systemctl start flanneld
systemctl status flanneld

ifconfig flannel.1

source /usr/k8s/bin/env.sh

 etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/config



 etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  ls ${FLANNEL_ETCD_PREFIX}/subnets
  
  
 etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  ls ${FLANNEL_ETCD_PREFIX}/subnets
  

 source /usr/k8s/bin/env.sh
 export KUBE_APISERVER="https://${MASTER_URL}"  
 export NODE_IP=192.168.224.184  



cat << EOF >> /etc/sysctl.conf
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF
modprobe br_netfilter
sysctl -p



 sudo yum install -y yum-utils \
  device-mapper-persistent-data \
  lvm2
  
 sudo yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
    
 yum -y install docker-ce
 


mv /usr/lib/systemd/system/docker.service /usr/lib/systemd/system/docker.service.bak
cat << EOF > /usr/lib/systemd/system/docker.service 

[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=notify
# the default is not to use systemd for cgroups because the delegate issues still
# exists and systemd currently does not support the cgroup feature set required
# for containers run by docker
EnvironmentFile=-/run/flannel/docker
ExecStart=/usr/bin/dockerd --log-level=info \$DOCKER_NETWORK_OPTIONS
ExecReload=/bin/kill -s HUP \$MAINPID
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
# Uncomment TasksMax if your systemd version supports it.
# Only systemd 226 and above support this version.
#TasksMax=infinity
TimeoutStartSec=0
# set delegate yes so that systemd does not reset the cgroups of docker containers
Delegate=yes
# kill only the docker process, not all processes in the cgroup
KillMode=process
# restart the docker process if it exits prematurely
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
EOF



systemctl daemon-reload
systemctl stop firewalld
systemctl disable firewalld
systemctl enable docker
systemctl start docker
systemctl status docker


cat << EOF > /etc/docker/daemon.json
{
    "registry-mirrors": ["https://registry.docker-cn.com"],
"max-concurrent-downloads": 10
}
EOF


systemctl daemon-reload

systemctl restart docker.service



 # 设置集群参数

 kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=bootstrap.kubeconfig


 # 设置客户端认证参数

 kubectl config set-credentials kubelet-bootstrap \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=bootstrap.kubeconfig


 # 设置上下文参数

 kubectl config set-context default \
  --cluster=kubernetes \
  --user=kubelet-bootstrap \
  --kubeconfig=bootstrap.kubeconfig


 # 设置默认上下文

 kubectl config use-context default --kubeconfig=bootstrap.kubeconfig


 mv bootstrap.kubeconfig /etc/kubernetes/





sudo mkdir /var/lib/kubelet 
cat > kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/usr/k8s/bin/kubelet \\
  --fail-swap-on=false \\
  --cgroup-driver=cgroupfs \\
  --address=${NODE_IP} \\
  --hostname-override=${NODE_IP} \\
  --experimental-bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \\
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
  --require-kubeconfig \\
  --cert-dir=/etc/kubernetes/ssl \\
  --cluster-dns=${CLUSTER_DNS_SVC_IP} \\
  --cluster-domain=${CLUSTER_DNS_DOMAIN} \\
  --hairpin-mode promiscuous-bridge \\
  --allow-privileged=true \\
  --serialize-image-pulls=false \\
  --logtostderr=true \\
  --v=2 \
  --pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google-containers/pause-amd64:3.0
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF




mv kubelet.service /etc/systemd/system/kubelet.service
systemctl daemon-reload
systemctl enable kubelet
systemctl start kubelet
systemctl status kubelet






 cat > kube-proxy-csr.json <<EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF





cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem \
  -ca-key=/etc/kubernetes/ssl/ca-key.pem \
  -config=/etc/kubernetes/ssl/ca-config.json \
  -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy

 sudo mv kube-proxy*.pem /etc/kubernetes/ssl/






 kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig



 kubectl config set-credentials kube-proxy \
  --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
  --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig




 kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig



 kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig


 mv kube-proxy.kubeconfig /etc/kubernetes/




 sudo mkdir -pv /var/lib/kube-proxy 

cat > kube-proxy.service <<EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/usr/k8s/bin/kube-proxy \\
  --bind-address=${NODE_IP} \\
  --hostname-override=${NODE_IP} \\
  --cluster-cidr=${SERVICE_CIDR} \\
  --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF




 mv kube-proxy.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kube-proxy
systemctl start kube-proxy
systemctl status kube-proxy













