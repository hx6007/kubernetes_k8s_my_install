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
















cat > /usr/k8s/bin/etcd_env.sh <<EOF
export NODE_NAME=etcd02 # 当前部署的机器名称(随便定义，只要能区分不同机器即可)
export NODE_IP=192.168.224.182 # 当前部署的机器IP
export NODE_IPS="192.168.224.181 192.168.224.182 192.168.224.183" # etcd 集群所有机器 IP
# etcd 集群间通信的IP和端口
export ETCD_NODES=etcd01=https://192.168.224.181:2380,etcd02=https://192.168.224.182:2380,etcd03=https://192.168.224.183:2380
EOF
 source /usr/k8s/bin/etcd_env.sh
 
 source /usr/k8s/bin/env.sh


 
cd /usr/local/src/
 wget https://github.com/etcd-io/etcd/releases/download/v3.3.9/etcd-v3.3.9-linux-amd64.tar.gz
 tar -xvf etcd-v3.3.9-linux-amd64.tar.gz
 sudo mv etcd-v3.3.9-linux-amd64/etcd* /usr/k8s/bin/
 



 sudo mkdir -pv /etc/etcd/ssl
 cd  /etc/etcd/ssl
cat > etcd-csr.json <<EOF
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "${NODE_IP}"
  ],
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
  -profile=kubernetes etcd-csr.json | cfssljson -bare etcd



sudo mkdir -pv /var/lib/etcd 
cd   /etc/systemd/system/
cat > etcd.service <<EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
ExecStart=/usr/k8s/bin/etcd \\
  --name=${NODE_NAME} \\
  --cert-file=/etc/etcd/ssl/etcd.pem \\
  --key-file=/etc/etcd/ssl/etcd-key.pem \\
  --peer-cert-file=/etc/etcd/ssl/etcd.pem \\
  --peer-key-file=/etc/etcd/ssl/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --initial-advertise-peer-urls=https://${NODE_IP}:2380 \\
  --listen-peer-urls=https://${NODE_IP}:2380 \\
  --listen-client-urls=https://${NODE_IP}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls=https://${NODE_IP}:2379 \\
  --initial-cluster-token=etcd-cluster-0 \\
  --initial-cluster=${ETCD_NODES} \\
  --initial-cluster-state=new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF


 

systemctl daemon-reload
systemctl enable etcd
systemctl start etcd
systemctl status etcd




for ip in ${NODE_IPS}; do
  ETCDCTL_API=3 /usr/k8s/bin/etcdctl \
  --endpoints=https://${ip}:2379  \
  --cacert=/etc/kubernetes/ssl/ca.pem \
  --cert=/etc/etcd/ssl/etcd.pem \
  --key=/etc/etcd/ssl/etcd-key.pem \
  endpoint health; done



 export NODE_IP=192.168.224.182  
 source /usr/k8s/bin/env.sh
 

cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "${NODE_IP}",
    "${MASTER_URL}",
    "${CLUSTER_KUBERNETES_SVC_IP}",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
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
  -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes

 
 sudo mkdir -pv /etc/kubernetes/ssl/
 sudo mv kubernetes*.pem /etc/kubernetes/ssl/


 
cat > token.csv <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF

 sudo mv token.csv /etc/kubernetes/




cat  > kube-apiserver.service <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
ExecStart=/usr/k8s/bin/kube-apiserver \\
  --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --advertise-address=${NODE_IP} \\
  --bind-address=0.0.0.0 \\
  --insecure-bind-address=${NODE_IP} \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=rbac.authorization.k8s.io/v1alpha1 \\
  --kubelet-https=true \\
  --enable-bootstrap-token-auth \\
  --token-auth-file=/etc/kubernetes/token.csv \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --service-node-port-range=${NODE_PORT_RANGE} \\
  --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem \\
  --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \\
  --client-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \\
  --etcd-cafile=/etc/kubernetes/ssl/ca.pem \\
  --etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem \\
  --etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem \\
  --etcd-servers=${ETCD_ENDPOINTS} \\
  --enable-swagger-ui=true \\
  --allow-privileged=true \\
  --apiserver-count=2 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/lib/audit.log \\
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \\
  --event-ttl=1h \\
  --logtostderr=true \\
  --v=6
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF


cat << EOF > /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1beta1 # This is required.
kind: Policy # Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
  # Log "pods/log", "pods/status" at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]

  # Don't log requests to a configmap called "controller-leader"
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]

  # Don't log watch requests by the "system:kube-proxy" on endpoints or services
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API group
      resources: ["endpoints", "services"]

  # Don't log authenticated requests to certain non-resource URL paths.
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" # Wildcard matching.
    - "/version"

  # Log the request body of configmap changes in kube-system.
  - level: Request
    resources:
    - group: "" # core API group
      resources: ["configmaps"]
    # This rule only applies to resources in the "kube-system" namespace.
    # The empty string "" can be used to select non-namespaced resources.
    namespaces: ["kube-system"]

  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]

  # Log all other resources in core and extensions at the Request level.
  - level: Request
    resources:
    - group: "" # core API group
    - group: "extensions" # Version of group should NOT be included.

  # A catch-all rule to log all other requests at the Metadata level.
  - level: Metadata
    # Long-running requests like watches that fall under this rule will not
    # generate an audit event in RequestReceived.
    omitStages:
      - "RequestReceived"
EOF


cp kube-apiserver.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kube-apiserver
systemctl start kube-apiserver
systemctl status kube-apiserver


cat > kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/k8s/bin/kube-controller-manager \\
  --address=127.0.0.1 \\
  --master=http://${MASTER_URL}:8080 \\
  --allocate-node-cidrs=true \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --cluster-cidr=${CLUSTER_CIDR} \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \\
  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem \\
  --root-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --leader-elect=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF


cp kube-controller-manager.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kube-controller-manager
systemctl start kube-controller-manager
systemctl status kube-controller-manager


cat > kube-scheduler.service <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/k8s/bin/kube-scheduler \\
  --address=127.0.0.1 \\
  --master=http://${MASTER_URL}:8080 \\
  --leader-elect=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF



cp kube-scheduler.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kube-scheduler
systemctl start kube-scheduler
systemctl status kube-scheduler





 yum install -y haproxy

mv /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak

cat << EOF > /etc/haproxy/haproxy.cfg
#---------------------------------------------------------------------
# Example configuration for a possible web application.  See the# full configuration options online.#
#   http://haproxy.1wt.eu/download/1.4/doc/configuration.txt
#
#---------------------------------------------------------------------
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # to have these messages end up in /var/log/haproxy.log you will
    # need to:
    #
    # 1) configure syslog to accept network log events.  This is done
    #    by adding the '-r' option to the SYSLOGD_OPTIONS in
    #    /etc/sysconfig/syslog
    #
    # 2) configure local2 events to go to the /var/log/haproxy.log
    #   file. A line like the following can be added to
    #   /etc/sysconfig/syslog
    #
    #    local2.*                       /var/log/haproxy.log
    #
    log         127.0.0.1 local2

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats
#---------------------------------------------------------------------# common defaults that all the 'listen' and 'backend' sections will# use if not designated in their block#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000
#---------------------------------------------------------------------
# main frontend which proxys to the backends
#---------------------------------------------------------------------
listen stats
  bind    *:9000
  mode    http
  stats   enable
  stats   hide-version
  stats   uri       /stats
  stats   refresh   30s
  stats   realm     Haproxy\ Statistics
  stats   auth      Admin:Password   #登陆需要账号密码

frontend k8s-api
    bind 192.168.224.182:443 # Master02 节点修改为 192.168.224.182
    mode tcp
    option tcplog
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    default_backend k8s-api

backend k8s-api
    mode tcp
    option tcplog
    option tcp-check
    balance roundrobin
    default-server inter 10s downinter 5s rise 2 fall 2 slowstart 60s maxconn 250 maxqueue 256 weight 100
    server k8s-api-1 192.168.224.181:6443 check
    server k8s-api-2 192.168.224.182:6443 check

frontend k8s-http-api
    bind 192.168.224.182:80 # Master02 节点修改为 192.168.224.182
    mode tcp
    option tcplog
    default_backend k8s-http-api

backend k8s-http-api
    mode tcp
    option tcplog
    option tcp-check
    balance roundrobin
    default-server inter 10s downinter 5s rise 2 fall 2 slowstart 60s maxconn 250 maxqueue 256 weight 100
    server k8s-http-api-1 192.168.224.181:8080 check
server k8s-http-api-2 192.168.224.182:8080 check
EOF


sed -i '15s/#//' /etc/rsyslog.conf
sed -i '16s/#//' /etc/rsyslog.conf
sed -i '74i\local2.*                                                /var/log/haproxy.log'  /etc/rsyslog.conf


systemctl restart rsyslog



systemctl start haproxy
systemctl enable haproxy
systemctl status haproxy




cat << EOF >> /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.ip_nonlocal_bind = 1
EOF
sysctl -p
cat /proc/sys/net/ipv4/ip_forward


 
yum install -y keepalived




mv /etc/keepalived/keepalived.conf /etc/keepalived/keepalived.conf.bak
cat << EOF > /etc/keepalived/keepalived.conf

cat << EOF > /etc/keepalived/keepalived.conf
! Configuration File for keepalived

global_defs {
   notification_email {
     root@localhost
   }
   notification_email_from haadmin@buhui.com
   smtp_server 127.0.0.1
   smtp_connect_timeout 30
   router_id node1
}

vrrp_script chk_haproxy {
    script "killall -0 haproxy"
    interval 2
    weight -5
}

vrrp_script chk_apiserver {
    script "killall -0 kube-apiserver"
    interval 2
    weight -5
}
vrrp_instance VI_1 {
    state BACKUP
    interface ens33
    virtual_router_id 51
    priority 98
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        192.168.224.186
    }
    # 调用vrrp_script定义的脚本
    track_script {
        chk_haproxy
        chk_apiserver
    }
}


virtual_server 192.168.224.186 80 {
  delay_loop 5
  lvs_sched wlc
  lvs_method NAT
  persistence_timeout 1800
  protocol TCP

  real_server 192.168.224.182 80 {
    weight 1
    TCP_CHECK {
      connect_port 80
      connect_timeout 3
    }
  }
}

virtual_server 192.168.224.186 443 {
  delay_loop 5
  lvs_sched wlc
  lvs_method NAT
  persistence_timeout 1800
  protocol TCP

  real_server 192.168.224.182 443 {
    weight 1
    TCP_CHECK {
      connect_port 80
      connect_timeout 3
    }
  }
}
EOF



systemctl start keepalived
systemctl enable keepalived
systemctl status keepalived



