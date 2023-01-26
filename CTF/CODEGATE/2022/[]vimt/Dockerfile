
   
FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y openssh-server gcc

RUN useradd ctf

RUN mkdir /home/ctf
ADD app /home/ctf

RUN mkdir /home/ctf/tmp

RUN chown root:root /home/ctf
RUN chmod 555 /home/ctf
RUN echo "/home/ctf/app" > /home/ctf/.bash_profile 
RUN echo "exit" >> /home/ctf/.bash_profile 

RUN chown root:root /home/ctf/app
RUN chown root:root /home/ctf/tmp
RUN chmod 640 /home/ctf/app
RUN chmod +x /home/ctf/app
RUN chmod u+s /home/ctf/app
RUN chmod 660 /home/ctf/tmp

RUN ssh-keygen -A
RUN mkdir -p /run/sshd
RUN echo 'ctf:ctf1234_smiley' | chpasswd
RUN chsh -s /bin/bash ctf

RUN chmod go-rx /usr/bin/wall
EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
