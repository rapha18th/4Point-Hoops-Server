FROM python:3.10

### Set up user with permissions
# Set up a new user named "user" with user ID 1000
RUN useradd -m -u 1000 user

# Switch to the "user" user
USER user

# Set home to the user's home directory
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

# Set the working directory to the user's home directory
WORKDIR $HOME/app

# Copy the current directory contents into the container at $HOME/app setting the owner to the user
COPY --chown=user . $HOME/app

### Set up app-specific content
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

### Update permissions for the app
USER root
RUN chmod 777 ~/app/*
USER user

CMD ["python", "main.py"]
