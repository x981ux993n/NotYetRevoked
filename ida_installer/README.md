# IDA Pro Installer Directory

This directory is for placing your IDA Pro installation files **before** building the Docker image.

## Purpose

IDA Pro will be installed **into the Docker image** during the build process, creating a self-contained, reproducible analysis environment.

## Supported Formats

Place **ONE** of the following in this directory:

### Option 1: .run Installer (Recommended)
```bash
cp /path/to/idapro_*_linux.run ./ida_installer/
```

Example: `idapro_9.0_linux.run`

### Option 2: .tar.gz Archive
```bash
cp /path/to/idapro_*.tar.gz ./ida_installer/
```

Example: `idapro_9.0_linux.tar.gz`

### Option 3: Pre-installed Directory
```bash
cp -r /existing/ida/installation ./ida_installer/ida/
```

The directory structure should be:
```
ida_installer/
└── ida/
    ├── ida64       # Main executable
    ├── python/     # IDAPython
    ├── plugins/
    └── ...
```

## Build Process

Once you've placed the installer here:

```bash
# Build Docker image (IDA will be installed into /opt/ida inside container)
docker-compose build

# Or use the setup script
./scripts/setup.sh
```

During the build, the Dockerfile will:
1. Detect the installer format
2. Install IDA to `/opt/ida` inside the container
3. Configure for headless operation
4. Clean up installer files

## Alternative: Volume Mount

If you **don't** place an installer here, you can still use an external IDA installation via volume mount:

```bash
# Install IDA to ./ida/ directory
./idapro_linux.run --prefix $(pwd)/ida

# Start container (docker-compose.yml mounts ./ida to /opt/ida)
docker-compose up -d

# IDA will be available from the host mount
```

## Verification

After building, verify IDA is installed:

```bash
# Check if IDA is in the image
docker-compose run --rm ida-analyzer /opt/ida/ida64 -v

# Or check the build logs
cat setup_logs/docker_build_*.log | grep "IDA"
```

## Security Note

**Do NOT commit IDA installers to version control!**

- IDA Pro is licensed software
- The installer files can be large (>500MB)
- This directory is excluded in `.gitignore`

## Troubleshooting

### "IDA not found during build"
- Ensure file is in `ida_installer/` directory
- Check filename matches supported formats
- Review build logs: `setup_logs/docker_build_*.log`

### "Permission denied" errors
```bash
chmod +x ida_installer/*.run
```

### "Installation failed"
Check if the .run installer supports `--mode unattended`:
```bash
./idapro_*_linux.run --help
```

Some installers may require different flags. Edit `Dockerfile` line ~85 to adjust.

## Size Considerations

The Docker image will be **large** (~2-4GB) with IDA included. This is normal and acceptable for a complete analysis environment.

To keep images smaller:
- Use the volume mount approach instead
- Use Docker layer caching effectively
- Build once, use many times

## License

Ensure you have a valid IDA Pro license before using this tool. The license file will typically be:
- In the IDA installation: `/opt/ida/ida.key`
- Or can be volume-mounted separately

---

**Ready to build?** Place your IDA installer here, then run `./scripts/setup.sh`
