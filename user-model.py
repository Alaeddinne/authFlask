class User(db.Model):
    __tablename__ = "users"
    Id = db.Column(db.String(30), unique=True, primary_key=True)
    Username = db.Column(db.String(100), unique=True, nullable=False)
    Password = db.Column(db.String(50), nullable=False)

    # def __init__(self, username, password):
    #     chars = string.ascii_lowercase+string.ascii_uppercase + \
    #         string.ascii_letters+string.digits
    #     self.Id = ''.join(random.choice(chars) for i in range(30))
    #     self.Username = username
    #     self.Password = password
