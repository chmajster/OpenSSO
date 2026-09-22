package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/config"
	"github.com/chmajster/OpenSSO/backend/internal/database"
	"github.com/chmajster/OpenSSO/backend/internal/httpapi"
	"github.com/redis/go-redis/v9"
)

func main(){
	log:=slog.New(slog.NewJSONHandler(os.Stdout,nil))
	cfg,e:=config.Load();if e!=nil{log.Error("configuration error","error",e);os.Exit(1)}
	ctx:=context.Background()
	db,e:=database.Open(ctx,cfg.DatabaseURL);if e!=nil{log.Error("database startup failed","error",e);os.Exit(1)};defer db.Close()
	if e=database.Migrate(ctx,db);e!=nil{log.Error("database migration failed","error",e);os.Exit(1)}
	ro,e:=redis.ParseURL(cfg.RedisURL);if e!=nil{log.Error("invalid redis URL","error",e);os.Exit(1)}
	rdb:=redis.NewClient(ro);defer rdb.Close();if e=rdb.Ping(ctx).Err();e!=nil{log.Error("redis startup failed","error",e);os.Exit(1)}
	s:=&http.Server{Addr:cfg.ListenAddr,Handler:httpapi.New(cfg,db,rdb,log).Handler(),ReadHeaderTimeout:10*time.Second,ReadTimeout:30*time.Second,WriteTimeout:30*time.Second,IdleTimeout:90*time.Second}
	go func(){log.Info("OpenSSO listening","address",cfg.ListenAddr);if err:=s.ListenAndServe();err!=nil&&err!=http.ErrServerClosed{log.Error("http server failed","error",err);os.Exit(1)}}()
	stop:=make(chan os.Signal,1);signal.Notify(stop,syscall.SIGINT,syscall.SIGTERM);<-stop
	shutdown,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
	if e=s.Shutdown(shutdown);e!=nil{log.Error("graceful shutdown failed","error",e)}
}
