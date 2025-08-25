package grpc

import (
	"context"
	"log"
	//"github.com/wycliff-ochieng/internal/service"
	//grpc "github.com/wycliff-ochieng/user_grpc/user_proto"
)

type Server struct {
	grpc.UnimplementedUserServiceRPCServer //forward compatibility
	Service                                *service.UserService
	Logger                                 *log.Logger
}

func NewServer(service *service.UserService, logger *log.Logger) *Server {
	return &Server{
		//rpc:     req,
		Service: service,
		Logger:  logger,
	}
}

func (s *Server) GetUserProfiles(ctx context.Context, req *grpc.GetUserRequest) (*grpc.GetUserProfileResponse, error) {
	s.Logger.Println("get profile for a user")

	//call user service for profile list
	profiles, err := s.Service.GetUserProfilesByUUIDs(ctx, req.Userid)
	if err != nil {
		s.Logger.Println("Issue getting user profiles from user-service")
		return nil, err
	}

	//convert Profiles struct to gRPC userProfile struct
	grpcProfile := make(map[string]*grpc.UserProfile)
	for _, p := range profiles {
		grpcProfile[p.UserID.String()] = &grpc.UserProfile{
			Userid:    p.UserID.String(),
			Firstname: p.Firstname,
			Lastname:  p.Lastname,
			Email:     p.Email,
		}
	}

	return &grpc.GetUserProfileResponse{Profiles: grpcProfile}, nil
}
