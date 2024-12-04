package dockerd

import (
  "context"
  "log"
	"os"
	"os/signal"
	"time"
	"github.com/docker/docker/api/types/image"
 	"github.com/docker/docker/api/types/container"
  "github.com/docker/docker/client"
  "honeypot-go-docker-ebpf/internal/models"
	"honeypot-go-docker-ebpf/internal/ip"
	"honeypot-go-docker-ebpf/build"
)

var portToContainer []string

// startContainer starts a container based on the port.
func startContainer(port uint16) {
  // Define a mapping between ports and image names
  portToImage := map[uint16]string{
    80:  "nginx:latest",
    443: "httpd:latest",
    22:  "alpine:latest",
  }

  imageName, exists := portToImage[port]
  if !exists {
    log.Printf("No container mapped for port: %d", port)
    return
  }

  cli, err := client.NewClientWithOpts(client.FromEnv)
  if err != nil {
    log.Fatalf("Failed to create Docker client: %v", err)
  }
  defer cli.Close()

  ctx := context.Background()

  log.Printf("Pulling image %s...", imageName)
  _, err = cli.ImagePull(ctx, imageName, image.PullOptions{})
  if err != nil {
    log.Fatalf("Failed to pull image %s: %v", imageName, err)
  }

  log.Printf("Creating container for image %s...", imageName)
  resp, err := cli.ContainerCreate(ctx, &container.Config{
    Image: imageName,
  }, nil, nil, nil, "")
  if err != nil {
    log.Fatalf("Failed to create container for image %s: %v", imageName, err)
  }

  log.Printf("Starting container %s...", resp.ID)
  err = cli.ContainerStart(ctx, resp.ID, container.StartOptions{})
  if err != nil {
    log.Fatalf("Failed to start container %s: %v", resp.ID, err)
  }

  log.Printf("Container started: %s", resp.ID)

  portToContainer[port] = resp.ID
}

func Cleanup() {
  log.Printf("Cleaning up services containers...")
  cli, err := client.NewClientWithOpts(client.FromEnv)
  if err != nil {
      log.Fatalf("Failed to create Docker client: %v", err)
  }
  defer cli.Close()

  for port, containerID := range portToContainer {
      log.Printf("Stopping container %s on port %d...", containerID, port)
      err := cli.ContainerStop(context.Background(), containerID, container.StopOptions{})
      if err != nil {
          log.Printf("Failed to stop container %s: %v", containerID, err)
      }

      log.Printf("Removing container %s...", containerID)
      err = cli.ContainerRemove(context.Background(), containerID, container.RemoveOptions{})
      if err != nil {
          log.Printf("Failed to remove container %s: %v", containerID, err)
      }
  }
}

func Monitor(objs *build.Packet_inspector_kernObjects){
	// Poll for packets continuously
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	for {
	  select {
      case <-stop:
        log.Printf("Received signal, exiting..")
        return
      default:
        // Attempt to read packets from the map
        for i := 0; i < 1024; i++ {
          var packet models.Packet_info
          err := objs.PacketMap.Lookup(uint32(i), &packet)
          if err == nil {
            if (packet.Dst_port == 80){
              log.Printf("Received packet: src: %s:%d, dst: %s:%d, len: %d",
                ip.IntToIP(packet.Src_ip), packet.Src_port,
                ip.IntToIP(packet.Dst_ip), packet.Dst_port,
                packet.Length,
              )

              startContainer(packet.Dst_port)
              ReinjectRawPacket(packet.RawData, iface)
            }
            
          }
        }
        time.Sleep(100 * time.Millisecond) // Avoid busy-waiting
	  }
	}
}