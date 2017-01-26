import os
import webapp2
import jinja2
from google.appengine.ext import db
import hmac
import re
from time import sleep

SECRET = 'randomkey'  # Secret to hmac

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)  # Create templates config


class Handler(webapp2.RequestHandler):
    """
    This class is a superclass to Handlers with some methods to render a
    template
    """

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class User(db.Model):
    """
    This class is a representation of a User in the datastore
    """
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()


class Post(db.Model):
    """
    This class is a representation of a Post in the datastore
    """
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    owner = db.ReferenceProperty(User, collection_name='posts')
    last_edit = db.DateTimeProperty(auto_now=True)


class Comment(db.Model):
    """
    This class is a representation of a comment in the datastore
    """
    content = db.StringProperty(required=True)
    owner = db.ReferenceProperty(User, collection_name='comments')
    created = db.DateTimeProperty(auto_now_add=True)
    post = db.ReferenceProperty(Post, collection_name='comments')
    last_edit = db.DateTimeProperty(auto_now=True)


class Like(db.Model):
    """
    This class is a representation of a Like in the datastore
    """
    owner = db.ReferenceProperty(User, collection_name='likes')
    post = db.ReferenceProperty(Post, collection_name='likes')


class MainPage(Handler):
    """
    this is a handler for the main page
    """

    def get(self):
        user = get_session_user(self)
        posts = Post.gql('order by created desc limit 10')

        self.render('list_post.html', posts=posts, user=user)


class NewPost(Handler):
    """
    this handler is for new posts on blog
    """

    def render_form(self, title='', body='', error=''):
        user = get_session_user(self)
        self.render('form.html', title=title, body=body, error=error,
                    user=user)

    def get(self):
        if not get_session_user(self):
            self.redirect('/login')
            return
        self.render_form()

    def post(self):
        user = get_session_user(self)
        if not user:
            self.redirect('/login')
            return
        title = self.request.get('subject')
        body = self.request.get('content')

        if title and body:
            new_post = Post(title=title, body=body, owner=user)
            new_post.put()
            sleep(0.1)  # wait commit
            self.redirect('/post/' + str(new_post.key().id()))
        else:
            error = 'We need the subject and the content'
            self.render_form(title=title, body=body, error=error)


class DeletePost(Handler):
    """
    this handler is for delete posts in the blog
    """

    def get(self):
        user = get_session_user(self)
        post = get_post_if_owner(self)
        if not post:
            return
        self.render('delete_post.html', post=post, user=user)

    def post(self):
        post = get_post_if_owner(self)
        if not post:
            return
        for comment in post.comments:
            comment.delete()
        for like in post.likes:
            like.delete()
        post.delete()
        sleep(0.1)  # wait commit
        self.redirect('/')


class EditPost(Handler):
    """
    This handler is for edit posts
    """

    def get(self):
        post = get_post_if_owner(self)
        user = get_session_user(self)
        if not post:
            return
        self.render('edit_post.html', title=post.title, body=post.body,
                    post_id=post.key().id(), user=user)

    def post(self):
        post = get_post_if_owner(self)
        user = get_session_user(self)
        if not post:
            return
        title = self.request.get('subject')
        body = self.request.get('content')

        if title and body:
            post.title = title
            post.body = body
            post.put()
            sleep(0.1)  # wait commit
            self.redirect('/post/' + str(post.key().id()))
        else:
            error = 'We need the subject and the content'
            self.render('edit_post.html', title=title, body=body, error=error,
                        post_id=post.key().id(), user=user)


def get_post_if_owner(handler):
    """
    this method help get a post only if the current user is the owner of the
    post
    """
    user = get_session_user(handler)
    if not user:
        handler.redirect('/login')
        return
    post_id = handler.request.get('post_id')
    post = Post.get_by_id(int(post_id))
    if not post.owner.username == user.username:
        handler.redirect('/')
        return
    return post


class PostHandler(Handler):
    """
    this handler is used to see the details of a Post
    """

    def get(self, post_id):
        post = Post.get_by_id(int(post_id))

        if not post:
            self.error(404)
        user = get_session_user(self)
        is_owner = False
        if user:
            is_owner = post.owner.username == user.username
        number_of_likes = post.likes.count()
        alredy_liked = False
        if user:
            if get_user_like_from_post(user, post):
                alredy_liked = True
        self.render('detail_post.html', post=post, user=user,
                    is_owner=is_owner, post_id=post.key().id(),
                    number_of_likes=number_of_likes, alredy_liked=alredy_liked)


class Signup(Handler):
    """
    this handler is for create new users
    """

    def get(self):
        user = get_session_user(self)
        if get_session_user(self):
            self.redirect('/welcome')
            return
        self.render('signup.html', user=user)

    def post(self):
        username_input = self.request.get('username')
        password_input = self.request.get('password')
        verify_input = self.request.get('verify')
        email_input = self.request.get('email')

        kw = {'email': email_input, 'username': username_input}

        has_error = False

        if not verify_pattern_string(r"^[a-zA-Z0-9_-]{3,20}$", username_input):
            kw['username_error'] = "That's not a valid username."
            has_error = True
        if not verify_pattern_string(r"^.{3,20}$", password_input):
            kw['password_error'] = "That wasn't a valid password."
            has_error = True
        if (not kw.get('password_error') and
                (not password_input == verify_input)):
            kw['verify_error'] = "Your passwords didn't match."
            has_error = True
        if email_input and (not verify_pattern_string(r"^[\S]+@[\S]+.[\S]+$",
                                                      email_input)):
            kw['email_error'] = "That's not a valid email."
            has_error = True
        q = User.gql('WHERE username = :username', username=username_input)
        has_user = q.get()
        if has_user:
            kw['username_error'] = "This user already exist"
            has_error = True

        if has_error:
            self.render('signup.html', **kw)
        else:
            db_password_hash = hash_string(password_input)
            new_user = User(username=username_input,
                            password=db_password_hash, email=email_input)
            new_user.put()
            new_user_id = str(new_user.key().id())

            cookie_value = generate_cookie(new_user_id)

            self.response.headers.add_header(
                'Set-Cookie', 'user=%s' % cookie_value)

            self.redirect('/welcome')


class Welcome(Handler):
    """
    this handler redirect the users to the welcome page
    """

    def get(self):
        cookie = str(self.request.cookies.get('user'))
        valid_user = verify_cookie(cookie)
        if valid_user:
            user = User.get_by_id(int(valid_user))
            self.render('welcome.html', user=user)
        else:
            self.response.headers.add_header('Set-Cookie', 'user=')
            self.redirect('/login')


class Login(Handler):
    """
    this handler is for user log in the SystemExit
    """

    def get(self):
        if get_session_user(self):
            self.redirect('/welcome')
            return
        self.render('login.html')

    def post(self):
        username_input = self.request.get('username')
        password_input = self.request.get('password')

        q = User.gql('WHERE username = :username', username=username_input)
        user = q.get()

        if user:
            if user.password == hash_string(password_input):
                cookie_value = generate_cookie(str(user.key().id()))

                self.response.headers.add_header(
                    'Set-Cookie', 'user=%s' % cookie_value)
                self.redirect('welcome')
                return
        self.render('login.html', username=username_input,
                    error='Invalid login')


class Logout(Handler):
    """
    this handler is for a user log out the system
    """

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')
        self.redirect('/login')


class NewComment(Handler):
    """
    this handler is for new comments in a Post
    """

    def get(self):
        post_id = self.request.get('post_id')
        post = Post.get_by_id(int(post_id))
        self.render('form_comment.html', post=post)

    def post(self):
        post_id = self.request.get('post_id')
        content = self.request.get('content')

        post = Post.get_by_id(int(post_id))

        if not post:
            self.redirect('/')
            return

        if not content:
            error = 'content needed'
            self.render('form_comment.html', error=error, content=content,
                        post=post)
            return

        user = get_session_user(self)

        comment = Comment(owner=user, post=post, content=content)

        comment.put()
        sleep(0.1)  # wait commit
        self.redirect('/post/' + post_id)


class EditComment(Handler):
    """
    this handler is for edit comments in a Post
    """

    def get(self):
        comment = get_comment_if_owner(self)
        comment_id = self.request.get('comment_id')
        post_id = comment.post.key().id()

        if not comment:
            return

        self.render('edit_comment.html', comment_id=comment_id,
                    content=comment.content, post_id=post_id)

    def post(self):
        comment = get_comment_if_owner(self)
        content = self.request.get('content')

        if not comment:
            return

        if not content:
            error = 'Content needed'
            comment_id = self.request.get('comment_id')
            self.render('edit_comment.html', comment_id=comment_id,
                        error=error, content=content)
            return
        comment.content = content
        comment.put()
        sleep(0.1)  # wait commit
        self.redirect(get_post_link_from_comment(comment))


class RemoveComment(Handler):
    """
    this handler is for remove comments in a Post
    """

    def get(self):
        comment = get_comment_if_owner(self)
        comment_id = self.request.get('comment_id')
        if not comment:
            return

        self.render('delete_comment.html', comment_id=comment_id,
                    content=comment.content)

    def post(self):
        comment = get_comment_if_owner(self)

        if not comment:
            return
        comment.delete()
        sleep(0.1)  # wait commit
        self.redirect(get_post_link_from_comment(comment))


class LikePost(Handler):
    """
    this handler is for like a Post
    """

    def post(self):
        user = get_session_user(self)
        if not user:
            self.redirect('/login')
            return
        post_id = self.request.get('post_id')
        post = Post.get_by_id(int(post_id))
        if not post or post.owner.key().id() == user.key().id():
            self.redirect('/')
            return
        like = get_user_like_from_post(user, post)
        if like:
            self.redirect('/post/' + str(post.key().id()))
            return
        like = Like(owner=user, post=post)
        like.put()
        sleep(0.1)  # wait commit
        self.redirect('/post/' + str(post.key().id()))


class UnlikePost(Handler):
    """
    this handler is for remove a like from a Post
    """

    def post(self):
        user = get_session_user(self)
        if not user:
            self.redirect('/login')
            return
        post_id = self.request.get('post_id')
        post = Post.get_by_id(int(post_id))
        if not post or post.owner.key().id() == user.key().id():
            self.redirect('/')
            return
        like = get_user_like_from_post(user, post)
        if not like:
            self.redirect('/post/' + str(post.key().id()))
            return
        like.delete()
        sleep(0.1)  # wait commit
        self.redirect('/post/' + str(post.key().id()))


def get_user_like_from_post(user, post):
    """
    get the likes of the user from the post
    """
    for like in user.likes:
        if like.post.key().id() == post.key().id():
            return like


def get_post_link_from_comment(comment):
    """
    get the link of a post from a comment
    """
    post_id = comment.post.key().id()
    return '/post/' + str(post_id)


def get_comment_if_owner(handler):
    """
    get comment if the current user is the owner
    """
    user = get_session_user(handler)
    if not user:
        handler.redirect('/login')
        return
    comment_id = handler.request.get('comment_id')
    comment = Comment.get_by_id(int(comment_id))
    if not comment and not comment.owner.username == user.username:
        handler.redirect('/')
        return
    return comment


def hash_string(s):
    """
    create a hash from a string using the SECRET
    """
    return hmac.new(SECRET, s).hexdigest()


def generate_cookie(s):
    """
    create a cookie from a string
    """
    generated_hash = hash_string(s)
    return '%s|%s' % (s, generated_hash)


def verify_cookie(cookie):
    """
    verify if the cookie is valid and return the cookiee's value
    """
    s = cookie.split('|')[0]
    is_valid = generate_cookie(s) == cookie
    if is_valid:
        return s
    else:
        return None


def get_session_user(handler):
    """
    get the current user
    """
    cookie = str(handler.request.cookies.get('user'))
    valid_user = verify_cookie(cookie)
    if valid_user:
        return User.get_by_id(int(valid_user))
    handler.response.headers.add_header('Set-Cookie', 'user=')


def verify_pattern_string(pattern, string):
    """
    verify if a string follow a pattern
    """
    RE = re.compile(pattern)
    return RE.match(string)

# start the app
app = webapp2.WSGIApplication([
    (r'/', MainPage),
    (r'/newpost', NewPost),
    (r'/post/(\d+)', PostHandler),
    (r'/signup', Signup),
    (r'/welcome', Welcome),
    (r'/login', Login),
    (r'/logout', Logout),
    (r'/delete', DeletePost),
    (r'/edit', EditPost),
    (r'/like', LikePost),
    (r'/unlike', UnlikePost),
    (r'/newcomment', NewComment),
    (r'/editcomment', EditComment),
    (r'/removecomment', RemoveComment)], debug=True)
