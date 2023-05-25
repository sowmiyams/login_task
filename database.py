from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = 'postgresql://cfvrbnsn:Vm29YEaSMKEX9Y_3GNloYNxLUkF8Rgsk@drona.db.elephantsql.com/cfvrbnsn'
#postgresql://rnhejpbs:***@drona.db.elephantsql.com/rnhejpbs

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
