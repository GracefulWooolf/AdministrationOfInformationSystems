
#!/bin/sh

mkdir -p /tmp/archiv/backup

if [ $# -eq 1 ]; then
	if [[ $1 != "/"* ]]; then
		echo "Путь относительный. Пожалуйста, введите абсолютный путь до каталога."
	else
		echo "Путь абсолютный"
		if [[ -d $1 ]]; then
			echo "Путь указан на каталог."
			#cp -r $1 /tmp/archiv/backup
			tar -cf /tmp/archiv/backup/$(date +"%Y-%m-%d-%H-%M-%S".tar) -C $(dirname $1) $(basename $1)
			if [[ $? -eq 0 ]]; then
				echo "Архив создан успешно."
			else
				echo "Ошибка при создании архива."
			fi
		else
			echo "Путь указан не на каталог. Пожалуйста, укажите путь до каталога, а не до файла."
		fi
	fi
else
	echo "Неправильно передано количество аргументов. Пожалуйста, передайте лишь один аргумент - полное имя каталога."
fi
