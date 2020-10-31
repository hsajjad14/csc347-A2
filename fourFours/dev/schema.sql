drop table account cascade;
drop table solution cascade;

create table account (
        id serial primary key,
        username varchar(50) UNIQUE,
        salt varchar(10) NOT NULL,
        passwd varchar(64) NOT NULL,
        firstName varchar(50),
        lastName varchar(50)
);

create table solution (
        id serial primary key,
        value integer not null,
	expression varchar(200) not null unique,
        accountId integer references account(id)
);

INSERT INTO account(firstName, lastName, username, salt, passwd) values('Alex','Large','bigBoy', 'h6S6TV9ZQO','3b9c2126a5f3215ddfd3b161eab25a6123474e92551ae5fccfa2ee9204e90817');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Anne','Lion','anne','qGgNELUsuR','515e2fa5c2f72841e182512fb478ee1a8bda82101a581d6071f8c08bded556a9');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Linda','Swim','lindah20','TADfXcfLTA','6dbb7841871b7bde916d1345b51d97bdf4f49ed02f827577ba2e2139bfd26b7f');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Abagail','Silver','coins','jDpXcl0NcM','228c3d15af0dbb2a6d850e6517b3180c8ba52c5e3c7a21822a739e2ad3b7c903');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Jessie','Burn','matchstick','B9rPf8COA0','db536d4060562e628c2ab0998dd795a201fcbaa8c16d9b7ab841640a14e02726');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Annie','Cup','coffee','6XS8yYPz6j','cd5eb0a20b0af30b2f3740bce277467eb366218e95672327453ec0e65f4070b1');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Diane','Bassell','ssll','cfGy4hdDid','91ba019881f0c31cc456ced60ae4919e87b8919606914b992930aa82cd95a97b');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Steve','Mountain','cliff', 'L1mVlAMucY','01b1dec23632c9ea7bd9d45882be9fc49aec125bb8323f6b3220c94b4716805a');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Arnold', 'Rosenbloom','arnold@cs.toronto.edu', 'VrcSdKaWCl', '9db7541217ec6cc86bdd3ffa906b4cea3c709fdddd2ab0ab72c08227016aa0c2');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Jay','Perlmuter','perl', 'z5f1HfTBv1','22f2ec05c3bfed8212c1303df70d92bb96f0d14dc7f98c9e2bae4050fd575b0e');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Peter','Piper','pickApeck', 'mm3le524vf','303bb13d6fa2ca6fa217b7be6912edf41911905edc1316c2a439e69f22d7b401');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Jen','Binghampton','hotel', 'BKy8F6cqxe','14cfaf39b2defad4354b32520821b1685e2b194f88b922b628f1de8ebbbeca56');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('David','Kleinman','dk@gmail.com', 'rYQqsGjO0w','2056790772b710a894e3d396d71c270e240b3d47edc7e7039711db52c877e791');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Jesse','Kowalski','eightball@gmail.com', 'YGqbQB8VHs','d3058165c9186658cc8c99bb664bf0a749b3edd2499968bf456ba4ecefe122ff');
INSERT INTO account(firstName, lastName, username, salt, passwd) values('Ivanna','Grant','ivanna', 'UTw035yFQL','d1cebe5afe1c24b3b1229ec4089f76755901250263d96554460cf58c9208fccd');
