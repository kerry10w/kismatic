package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/apprenda/kismatic/pkg/install"
	"github.com/apprenda/kismatic/pkg/ssh"
	"github.com/apprenda/kismatic/pkg/util"
	"github.com/spf13/cobra"
)

type diagsOpts struct {
	planFilename string
}

// NewCmdDiagnostic collects diagnostic data on remote nodes
func NewCmdDiagnostic(out io.Writer) *cobra.Command {
	opts := &diagsOpts{}

	cmd := &cobra.Command{
		Use:   "diags",
		Short: "Collects diagnostic about the nodes in the cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("Unexpected args: %v", args)
			}

			return doDiagnostics(out, opts)
		},
	}

	// PersistentFlags
	cmd.PersistentFlags().StringVarP(&opts.planFilename, "plan-file", "f", "kismatic-cluster.yaml", "path to the installation plan file")

	return cmd
}

// diagCmd is a struct to hold a command, cmd info and filename to run diagnostic on
type diagCmd struct {
	info     string
	cmd      string
	filename string
	canFail  bool
}

var hostCmds = []diagCmd{
	{"Getting date", "date", "date", false},
	{"Getting hostname", "hostname", "hostname", false},
	{"Dumping /etc/hosts", "cat /etc/hosts", "hosts_file", false},
}

var dockerCmds = []diagCmd{
	{"Dumping docker.service status", "sudo systemctl status docker", "systemd_docker", false},
	{"Dumping journal for docker.service", "sudo journalctl -u docker.service --no-pager", "journalctl_docker", false},
	{"Dumping docker ps", "sudo docker ps -a", "docker_ps", false},
	{"Dumping docker images", "sudo docker images", "docker_images", false},
}

var k8sCmds = []diagCmd{
	{"Dumping kubelet.service status", "sudo systemctl status kubelet", "systemd_kubelet", false},
	{"Dumping journal for kubelet.service", "sudo journalctl -u kubelet.service --no-pager", "journalctl_kubelet", false},
	{"Dumping kube-proxy docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_kube-proxy --format={{.ID}} -l`", "logs_kube_proxy", false},
}

var k8sMasterCmds = []diagCmd{
	{"Dumping kube-apiserver docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_kube-apiserver --format={{.ID}} -l`", "logs_kube_apiserver", false},
	{"Dumping kube-controller-manager docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_kube-controller-manager --format={{.ID}} -l`", "logs_kube_controller_manager", false},
	{"Dumping kube-scheduler docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_kube-scheduler --format={{.ID}} -l`", "logs_kube_scheduler", false},
	{"Dumping nodes", "sudo kubectl get nodes", "kubectl_nodes", false},
	{"Dumping apis", "sudo kubectl get api-versions", "kubectl_apis", false},
	{"Dumping pods", "sudo kubectl get pods -n kube-system", "kubectl_pods", false},
	{"Dumping services", "sudo kubectl get services -n kube-system", "kubectl_services", false},
	{"Dumping daemonsets", "sudo kubectl get ds -n kube-system", "kubectl_daemonset", false},
	{"Dumping deployments", "sudo kubectl get deployments -n kube-system", "kubectl_deployments", false},
}

var k8sWorkloadCmds = []diagCmd{
	{"Dumping kube-dashboard docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_kubernetes-dashboard --format={{.ID}} -l`", "logs_kubernetes_dashboard", true},
	{"Dumping kubedns docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_kubedns --format={{.ID}} -l`", "logs_kubedns", true},
	{"Dumping dnsmasq docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_dnsmasq --format={{.ID}} -l`", "logs_dnsmasq", true},
	{"Dumping dns-healthz docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_healthz --format={{.ID}} -l`", "logs_kube_healthz", true},
}

var calicoCmds = []diagCmd{
	{"Dumping calico-node docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_calico-node --format={{.ID}} -l`", "logs_calico_node", false},
	{"Dumping calico-cni docker logs", "sudo docker logs `sudo docker ps -a -f name=k8s_install-cni --format={{.ID}} -l`", "logs_calico_cni", false},
	{"Dumping netstat", "sudo netstat --all --numeric", "netstat", false},
	{"Dumping routes", "sudo route", "route", false},
	{"Dumping routes (IPv4)", "sudo ip -4 route", "ipv4_route", false},
	{"Dumping routes (IPv6)", "sudo ip -6 route", "ipv6_route", false},
	{"Dumping interface info (IPv4)", "sudo ip -4 addr", "ipv4_addr", false},
	{"Dumping interface info (IPv6)", "sudo ip -6 addr", "ipv6_addr", false},
	{"Dumping iptables (IPv4)", "sudo iptables-save", "ipv4_tables", false},
	{"Dumping iptables (IPv6)", "sudo ip6tables-save", "ipv6_tables", false},
	{"Dumping ipsets", "sudo ipset list", "ipsets", false},
}

var etcdCmds = []diagCmd{
	{"Dumping etcd_k8s.service status", "sudo systemctl status etcd_k8s", "systemd_etcd_k8s", false},
	{"Dumping journal for etcd_k8s.service", "sudo journalctl -u etcd_k8s.service --no-pager", "journalctl_etcd_k8s", false},
	{"Getting etcd_networking health", "sudo /usr/bin/etcdctl --endpoint='https://127.0.0.1:6666/' --cert-file=/etc/etcd_networking/etcd.pem --key-file=/etc/etcd_networking/etcd-key.pem --ca-file=/etc/etcd_networking/ca.pem cluster-health", "etcd_k8s_health", false},
	{"Dumping etcd_networking.service status", "sudo systemctl status etcd_networking", "systemd_etcd_networking", false},
	{"Dumping journal for etcd_networking.service", "sudo journalctl -u etcd_networking.service --no-pager", "journalctl_etcd_networking", false},
	{"Getting etcd_networking health", "sudo /usr/bin/etcdctl --endpoint='https://127.0.0.1:6666/' --cert-file=/etc/etcd_networking/etcd.pem --key-file=/etc/etcd_networking/etcd-key.pem --ca-file=/etc/etcd_networking/ca.pem cluster-health", "etcd_networking_health", false},
}

func doDiagnostics(out io.Writer, opts *diagsOpts) error {
	planFile := opts.planFilename
	planner := install.FilePlanner{File: planFile}

	// Read plan file
	if !planner.PlanExists() {
		util.PrettyPrintErr(out, "Reading plan file")
		return fmt.Errorf("plan file %q does not exist", planFile)
	}
	util.PrettyPrintOk(out, "Reading plan file")
	plan, err := planner.Read()
	if err != nil {
		util.PrettyPrintErr(out, "Reading plan file")
		return fmt.Errorf("error reading plan file %q: %v", planFile, err)
	}

	// Validate SSH connectivity to nodes
	if ok, errs := install.ValidatePlanSSHConnections(plan); !ok {
		util.PrettyPrintErr(out, "Validate SSH connectivity to nodes")
		util.PrintValidationErrors(out, errs)
		return fmt.Errorf("SSH connectivity validation errors found")
	}
	util.PrettyPrintOk(out, "Validate SSH connectivity to nodes")

	// Get versions as only supported nodes are >1.3
	cv, err := install.ListVersions(plan)
	if err != nil {
		return fmt.Errorf("error listing cluster versions: %v", err)
	}
	var toDiagnose []install.ListableNode
	var toSkip []install.ListableNode
	for _, n := range cv.Nodes {
		if install.IsOlderThanVersion(n.Version, "v1.2.0") {
			toDiagnose = append(toDiagnose, n)
		} else {
			toSkip = append(toSkip, n)
		}
	}

	// Print the nodes that will be skipped
	if len(toSkip) > 0 {
		util.PrintHeader(out, "Skipping nodes that are not eligible", '=')
		for _, n := range toSkip {
			util.PrettyPrintOk(out, "- %q is at an unsupported version %q", n.Node.Host, n.Version)
		}
		fmt.Fprintln(out)
	}

	// Print message if there's no work to do
	if len(toDiagnose) == 0 {
		fmt.Fprintln(out, "All nodes have an unsupported version")
	} else {
		return diagnoseNodes(out, plan, opts, toDiagnose)
	}

	return nil
}

func diagnoseNodes(out io.Writer, plan *install.Plan, opts *diagsOpts, nodesToDiagnose []install.ListableNode) error {
	now := time.Now().Format("20060102_150405")
	for _, n := range nodesToDiagnose {
		cmdsToRun := []diagCmd{}
		cmdsToRun = append(cmdsToRun, hostCmds...)
		if n.HasRoles("etcd") {
			cmdsToRun = append(cmdsToRun, etcdCmds...)
		}
		// Maybe masters were uncordoned, run k8sWorkloadCmds on all nodes
		if n.HasRoles("master", "worker", "ingress", "storage") {
			cmdsToRun = append(cmdsToRun, dockerCmds...)
			cmdsToRun = append(cmdsToRun, calicoCmds...)
			cmdsToRun = append(cmdsToRun, k8sCmds...)
			cmdsToRun = append(cmdsToRun, k8sWorkloadCmds...)
		}
		// Master specific commands
		if n.HasRoles("master") {
			cmdsToRun = append(cmdsToRun, k8sMasterCmds...)
		}
		diagsDir := fmt.Sprintf("diags-%s-%s", n.Node.Host, now)
		tmpDir := fmt.Sprintf("/tmp/%s", diagsDir)
		util.PrintHeader(out, fmt.Sprintf("Collecting Diagnostics: %q %q", n.Node.Host, n.Roles), '=')
		// Get an SSH client
		sshDeets := plan.Cluster.SSH
		client, err := ssh.NewClient(n.Node.IP, sshDeets.Port, sshDeets.User, sshDeets.Key)
		if err != nil {
			util.PrettyPrintErr(out, "Creating SSH client: %v", err)
		} else {
			//Create a temp directory on remote
			newDirCmd := []string{"sudo", "mkdir", tmpDir, "&&", "sudo", "chmod", "777", tmpDir}
			o, dirErr := client.Output(false, newDirCmd...)
			if dirErr != nil {
				util.PrettyPrintErr(out, "Creating directory %q: %v", tmpDir, dirErr)
				util.PrintColor(out, util.Red, "  %v", o)
			} else {
				util.PrettyPrintOk(out, "Creating directory %q", tmpDir)
				// Run the commands
				for _, cmd := range cmdsToRun {
					if o, err := writeDiags(client, cmd, tmpDir); err != nil {
						if cmd.canFail {
							util.PrettyPrintSkipped(out, cmd.info)
						} else {
							util.PrettyPrintErr(out, "%s: %v", cmd.info, err)
							util.PrintColor(out, util.Red, "%v", o)
						}
					} else {
						util.PrettyPrintOk(out, cmd.info)
					}
				}
				// Tar up diagnostics
				tarFile := fmt.Sprintf("%s.tar.gz", diagsDir)
				tarFilePath := filepath.Join("/tmp", tarFile)
				o, err = client.Output(false, "sudo", "tar", "-zcvf", tarFilePath, "-C", tmpDir, ".")
				if err != nil {
					util.PrettyPrintErr(out, "Compressing the diagnostics: %v", err)
					util.PrintColor(out, util.Red, "%v", o)
				} else {
					util.PrintColor(out, util.Green, fmt.Sprintf("Diagnostics saved on remote machine %q to %q\n", n.Node.Host, tarFilePath))
					// setup a local directory for diagnostics
					pwd, _ := os.Getwd()
					diagsDir := filepath.Join(pwd, "diagnostics", now)
					localTar := filepath.Join(diagsDir, fmt.Sprintf("%s.tar.gz", n.Node.Host))
					if err := os.MkdirAll(diagsDir, 0777); err != nil {
						util.PrintColor(out, util.Red, "Copying tar from remote machine: %v", err)
					} else {
						// scp to local
						o, err := client.CopyFromRemote(tarFilePath, localTar)
						if err != nil {
							util.PrettyPrintErr(out, "Copying tar from remote machine: %v", err)
							util.PrintColor(out, util.Red, "%v", o)
						} else {
							util.PrintColor(out, util.Green, fmt.Sprintf("Copying tar from remote machine %q to %q\n", n.Node.Host, localTar))
						}
					}
				}
			}
		}
	}
	return nil
}

// writeDiags executes the dignostic commans and outputs the result in the file
func writeDiags(client ssh.Client, cmd diagCmd, dir string) (string, error) {
	// run command and redirect both stdout and stderr to a file
	cmdToRun := []string{cmd.cmd, "&>", filepath.Join(dir, cmd.filename)}
	return client.Output(false, cmdToRun...)
}
