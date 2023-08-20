# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import logging
from datetime import datetime

import json

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
logging.basicConfig(level=logging.DEBUG)

class Users(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(64), nullable=True)
    password = db.Column(db.Text())
    jwt_auth_active = db.Column(db.Boolean())
    date_joined = db.Column(db.DateTime(), default=datetime.utcnow)

    def __repr__(self):
        return f"User {self.username}"

    def save(self):
        db.session.add(self)
        db.session.commit()

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def update_email(self, new_email):
        self.email = new_email

    def update_username(self, new_username):
        self.username = new_username

    def check_jwt_auth_active(self):
        return self.jwt_auth_active

    def set_jwt_auth_active(self, set_status):
        self.jwt_auth_active = set_status

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter_by(email=email).first()
    
    @classmethod
    def get_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    def toDICT(self):

        cls_dict = {}
        cls_dict['_id'] = self.id
        cls_dict['username'] = self.username
        cls_dict['email'] = self.email

        return cls_dict

    def toJSON(self):

        return self.toDICT()


class JWTTokenBlocklist(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    jwt_token = db.Column(db.String(), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False)

    def __repr__(self):
        return f"Expired Token: {self.jwt_token}"

    def save(self):
        db.session.add(self)
        db.session.commit()

class Questions(db.Model):
    questionNumber = db.Column(db.Integer(), primary_key=True)
    question = db.Column(db.Text(), nullable=True)
    choices = db.Column(db.Text(), nullable=True)
 
    def __repr__(self):
        return f"Question Number {self.questionNumber}"

    def save(self):
        db.session.add(self)
        db.session.commit()


    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def get_by_QNum(cls, questionNumber):
        # Convert the question_number_str to an integer

        try:
            question_num = int(questionNumber)
            logging.debug("get_by_QNum - Valid Question Number:"+str(question_num))           
        except ValueError:
            # Handle the case when the question_number_str cannot be converted to an integer
            print("Invalid question number:", questionNumber)
            logging.debug("get_by_QNum - Valid Question Number:"+question_num)
        return cls.query.filter_by(questionNumber=question_num).first()
    
    @classmethod
    def get_questions(cls):
        questions_tuple = cls.query.all() 
 
        #questions_tuple = (question1, question2, ...)  # Replace with actual instances

        # Convert each question object to a dictionary
        questions_dict_list = [
            {
                "questionNumber": question.questionNumber,
                "question": question.question,
                "choices": question.choices
            }
            for question in questions_tuple
        ]

        # Convert the list of dictionaries to a JSON-formatted string
        questions_json_string = json.dumps(questions_dict_list)


        logging.debug("get_questions:"+questions_json_string)       
         # Convert each question object to a dictionary and then to JSON

        # Now you can return the list of JSON-formatted questions
        return questions_dict_list  


    def toDICT(self):

        cls_dict = {}
        cls_dict['questionNumber'] = self.questionNumber
        cls_dict['question'] = self.question
        cls_dict['choices'] = self.choices

        return cls_dict

    def toJSON(self):

        return json.dumps(self.toDICT());

class UserAnswers(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    userid = db.Column(db.Integer(), nullable=False)
    questionNumber = db.Column(db.Text(), nullable=False)  # Match the column name
    AnswerChoice = db.Column(db.Text(), nullable=False)
 
    def __repr__(self):
        return f"UserAnswer {self.id}"

    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
            logging.debug("Saved UserAnswer to database: " + str(self))
        except Exception as e:
            db.session.rollback()
            logging.error("Error saving UserAnswer to database: " + str(e))
            raise

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

    @classmethod
    def get_by_QNum(cls, userid,questionNumber):
        # Convert the question_number_str to an integer

        try:
            question_num = int(questionNumber)
            logging.debug("get_by_QNum - Valid Question Number:"+str(question_num))           
        except ValueError:
            # Handle the case when the question_number_str cannot be converted to an integer
            print("Invalid question number:", questionNumber)
            logging.debug("get_by_QNum - Valid Question Number:"+question_num)
        return cls.query.filter_by(userid=userid , questionNumber=question_num).first()
    
    @classmethod
    def get_useranswers(cls,userid):
        useranswers_tuple = cls.query.filter_by(userid=userid) ;
 
        #questions_tuple = (question1, question2, ...)  # Replace with actual instances

        # Convert each useranswer object to a dictionary
        useranswers_dict_list = [
            {
                "questionNumber": useranswer.questionNumber,
                "AnswerChoice": useranswer.AnswerChoice,
                "userid": useranswer.id
            }
            for useranswer in useranswers_tuple
        ]

        # Convert the list of dictionaries to a JSON-formatted string
        useranswer_json = json.dumps(useranswers_dict_list)


        logging.debug("get_questions:"+useranswer_json)       
         # Convert each question object to a dictionary and then to JSON

        # Now you can return the list of JSON-formatted questions
        return useranswers_dict_list;  


    def toDICT(self):

        cls_dict = {}
        cls_dict['questionNumber'] = self.questionNumber
        cls_dict['AnswerChoice'] = self.AnswerChoice
        cls_dict['userid'] = self.userid

        return cls_dict

    def toJSON(self):

        return json.dumps(self.toDICT());
