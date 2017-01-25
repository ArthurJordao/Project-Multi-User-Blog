# Project: Multi User Blog
## Description
This project is a blog written in python with the framework google app engine.
* It list the posts in the path /.
* You can create a user in /login.
* If you are loged you can create a post in /newpost.
* When you're in the detail of a post you if you're the owner you can remove and edit it
* In the comments session you can comment if you're loged and you can edit and remove your comments

## Run

1. You need to install the [google app engine](https://cloud.google.com/appengine/docs/python/download)
 and the [python2.7](https://www.python.org/downloads/)
2. Clone this repository or download the zip and unzip it
3. Enter in the project's folder
4. Run the programm with the command
```
dev_appserver.py app.yaml
```
5. You can open your browser in the localhost:8080 and see the blog working


## Example
You can see a example of the blog in this [link](https://blog-156411.appspot.com/)