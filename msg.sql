create table channels (
	"channelid" text primary key not null,
	"url" text not null
);

create table mentions (
	"mentionid" text primary key not null,
	"code" text not null
);

create table presets (
	"presetid" text primary key not null,
	"channelid" text not null,
	"mentionid" text,
	"message" text not null
);

create table crontab (
	"seqno" integer primary key,
	"descr" text,
	"schema" text not null,
	"presetid" text not null
);
