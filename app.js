const express = require('express');
const app = express();
const connection = require('./src/database');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const SECRET_KEY = require('./src/secret');
const verifyToken = require('./src/auth');
// const moment= require('moment');
const moment = require('moment-timezone');

const cors = require('cors');

// Middleware para analizar el cuerpo de las solicitudes

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Ruta para registro de usuarios
app.post('/register', async (req, res) => {
  const { curp, rfc, nombre, paterno, materno, sexo, cp, estado, ciudad, colonia, calle, telefono, email, password  } = req.body;

  // Hacer todas las validaciones posibles
  if (!password) {
    res.status(400).json({ error: 'Debe proporcionar una contraseña' });
    return;
  }

  try {
    // Generar un ID unico para el usuario
    const userId = uuidv4();

    // Encriptar la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Logica para insertar el nuevo usuario en la base de datos
    const query = 'INSERT INTO usuarios (id, curp, rfc, nombre, paterno, materno, sexo, cp, estado, ciudad, colonia, calle, telefono, email, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
    const values = [userId, curp, rfc, nombre, paterno, materno, sexo, cp, estado, ciudad, colonia, calle, telefono, email, hashedPassword];

    connection.query(query, values, (err, result) => {
      if (err) {
        console.error('Error al registrar usuario: ', err);
        res.status(500).json({ error: 'Error al registrar usuario' });
        return;
      }
      res.status(200).json({ message: 'Usuario registrado correctamente' });
    });
  } catch (err) {
    console.error('Error al registrar usuario: ', err);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
})

// Ruta para logear al usuario
app.post('/login', async (req, res) => {
  const { curp, password } = req.body;

  try {
    // Logica para buscar al usuario en la base de datos
    const query = 'SELECT * FROM usuarios WHERE curp = ?';
    const values = [curp];

    connection.query(query, values, async (err, result) => {
      if (err) {
        console.error('Error al iniciar sesión: ', err);
        res.status(500).json({ error: 'Error al iniciar sesión' });
        return;
      }

      if (result.length === 0) {
        res.status(401).json({ error: 'Credenciales inválidas' });
        return;
      }
      const user = result[0];

      // Verficar la contraseña encriptada
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        res.status(401).json({ error: 'Credenciales inválidas' });
        return;
      }

      // Generar un token JWT
      const token = jwt.sign({ userId: user.curp }, SECRET_KEY, { expiresIn: '1h' });

      res.status(200).json({ token: token, curp: user.curp });
    });
  } catch(err) {
    console.error('Error al iniciar sesión: ', err);
    res.status(500).json({ error: 'Eror al iniciar sesión' });
  }
});


// Ver usuario por su curp
app.get('/usuario/:curp', verifyToken, (req, res) => {
  const curp = req.params.curp;

  const query = 'SELECT * FROM usuarios WHERE curp = ?';
  const values = [curp];

  connection.query(query, values, (err, results) => {
    if (err) {
      console.error('Error al obtener usuario: ', err);
      res.status(500).json({ error: 'Error al obtener usuario' });
      return;
    }

    if (results.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    const user = results[0];
    const { id, curp, rfc, nombre, paterno, materno, sexo, cp, estado, ciudad, colonia, calle, telefono, email } = user;

    res.status(200).json({
      id,
      curp,
      rfc,
      nombre,
      paterno,
      materno,
      sexo,
      cp,
      estado,
      ciudad,
      colonia,
      calle,
      telefono,
      email
    });
  });
});


// Registrar eventos
app.post('/registrar-eventos', (req, res) => {
  let { nombre, descripcion, ubicacion, tipo, fecha, hora } = req.body;

  // Validar que se proporcionaron todos los campos requeridos
  if (!nombre || !descripcion || !ubicacion || !tipo || !fecha || !hora) {
    res.status(400).json({ error: 'Todos los campos son requeridos' });
    return;
  }

  // Generar un ID unico para el evento
  const idEvento = uuidv4();

  // Convertir la fecha a formato ISO y eliminar la 'Z' al final
  fecha = new Date(fecha).toISOString().split('T')[0];
  // fecha = moment(fecha).format('YYYY-MM-DD');

  // Convertir la hora a formato 'HH:MM:SS'
  hora = moment(hora, 'HH:mm:ss').format('HH:mm:ss');

  // Lógica para insertar el nuevo evento en la base de datos
  const query = 'INSERT INTO eventos (id, nombre, descripcion, ubicacion, tipo, fecha, hora) VALUES (?, ?, ?, ?, ?, ?, ?)';
  const values = [idEvento, nombre, descripcion, ubicacion, tipo, fecha, hora];

  connection.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al registrar evento: ', err);
      res.status(500).json({ error: 'Error al registrar evento' });
      return;
    }
    res.status(200).json({ message: 'Evento registrado correctamente' });
  });
});


app.get('/eventos/:id', verifyToken, (req, res) => {
  const idEvento = req.params.id;

  const query = 'SELECT * FROM eventos WHERE id = ?';
  const values = [idEvento];

  connection.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al obtener evento: ', err);
      res.status(500).json({ error: 'Error al obtener evento' });
      return;
    }

    if (result.length === 0) {
      res.status(404).json({ error: 'Evento no encontrado' });
      return;
    }

    const evento = result[0];
    res.status(200).json(evento);
  })
})

// Mostrar todos los eventos
app.get('/eventos', (req, res) => {
  const query = 'SELECT * FROM eventos';

  connection.query(query, (err, result) => {
    if(err) {
      console.error('Error al obtener eventos: ', err);
      res.status(500).json({ error: 'Error al obtener eventos' });
      return;
    }

    res.status(200).json(result);
  })
});


app.get('/evento/proximoEvento', (req, res) => {
  const currentDate = new Date();

  const query = `SELECT * FROM eventos WHERE fecha > ? OR (fecha = ? AND hora >= ?) ORDER BY fecha ASC, hora ASC LIMIT 1`;

  connection.query(
    query, [currentDate, currentDate, currentDate.toLocaleTimeString()],
    (err, result) => {
      if (err) {
        console.error('Error al obtener el proximo evento: ', err);
        res.status(500).json({ error: 'Error al obtener el próximo evento' });
        return;
      }
      if (result.length === 0) {
        res.status(404).json({ error: 'No hay eventos futuros registrados' });
        return;
      }

      res.status(200).json(result[0]);
    }
  );
});



// Registrar usuarios en eventos
app.post('/eventos/:id/registrar', verifyToken, (req, res) => {
  const idEvento = req.params.id;
  const curp = req.userId;

  // Verificar si el evento existe
  const checkEventQuery = 'SELECT * FROM eventos WHERE id = ?';
  connection.query(checkEventQuery, [idEvento], (err, eventResults) => {
    if (err) {
      console.error('Erro al verificar el evento: ', err);
      res.status(500).json({ error: 'Error al verificar el evento' });
      return;
    }
    if (eventResults.length === 0) {
      res.status(404).json({ error: 'Evento no encontrado' });
      return;
    }

    // Generar un ID unico para el registro
    const registroID = uuidv4();

    // Registrar al usuario en el evento
    const registerQuery = 'INSERT INTO usuarios_eventos (id, curp, evento_id) VALUES (?, ?, ?)';
    const values = [registroID, curp, idEvento];

    connection.query(registerQuery, values, (err, result) => {
      if (err) {
        console.error('Error al registrar usuario en el evento: ', err);
        res.status(500).json({ error: 'Erro al registrar usuario en el evento' });
        return;
      }

      res.status(200).json({ message: 'Usuario registrado en el evento correctamente', registroID });
    })
  })
});


// Registrar asistencia del usuario al evento
app.post('/eventos/:id/asistencia', verifyToken, (req, res) => {
  const idEvento = req.params.id;
  const curp = req.userId;

  // Verificar si el evento existe
  const checkEventQuery = 'SELECT * FROM eventos WHERE id = ?';
  connection.query(checkEventQuery, [idEvento], (err, eventResults) => {
    if (err) {
      console.error('Error al verfiicar el evento: ', err);
      res.status(500).json({ error: 'Error al verificar el evento' });
      return;
    }

    if (eventResults.length === 0) {
      res.status(404).json({ error: 'Evento no encontrado' });
    }

    // Generar un ID unico para el registro de asistencia
    const asistenciaId = uuidv4();

    // Obtener la fecha y hora actual

    let fechaHoraActual = moment().tz('America/Mexico_City').format('YYYY-MM-DD HH:mm:ss');

    // Registrar la asistencia del usuario al evento
    const registerQuery = 'INSERT INTO asistencia (id, usuario_curp, evento_id, fecha_hora_asistencia) VALUES (?, ?, ?, ?)';
    const values = [asistenciaId, curp, idEvento, fechaHoraActual];

    connection.query(registerQuery, values, (err, result) => {
      if (err) {
        console.error('Error al registrar asistencia: ', err);
        res.status(500).json({ error: 'Error al registrar asistencia' });
        return;
      }
      res.status(200).json({ message: 'Asistencia registrada correctamente' })
    });
  });
});

app.get('/usuarios/:curp/eventos/proximoEvento', verifyToken, (req, res) => {
  const curp = req.params.curp;
  const currentDate = new Date(); // OBtener la fecha y hora actuales

  // Verificar si el usuario existe
  const checkUserQuery = 'SELECT * FROM usuarios WHERE curp = ?';
  connection.query(checkUserQuery, [curp], (err, result) => {
    if (err) {
      console.error('Error al verificar el usuario: ', err);
      res.status(500).json({ error: 'Error al verificar el usuario' });
      return;
    }

    if (result.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }
    // Obtener el proximo evento registrado para el usuario
    const getNextEventQuery = `SELECT e.* FROM eventos e INNER JOIN usuarios_eventos ue ON e.id = ue.evento_id WHERE ue.curp = ? AND (e.fecha > ? OR (e.fecha = ? AND e.hora >= ?)) ORDER BY e.fecha ASC, e.hora ASC LIMIT 1`;
    connection.query(getNextEventQuery, [curp, currentDate, currentDate, currentDate.toLocaleTimeString()], (err, result) => {
      if (err) {
        console.error('Error al obtener el proximo evento del usuario: ', err);
        res.status(500).json({ error: 'Error al obtener el próximo evento del usuario' });
        return;
      }

      if (result.length === 0) {
        res.status(404).json({ error: 'Usuario no está registrado en ningún evento' });
        return;
      }
      res.status(200).json(result[0]);
    })
  });
});

app.listen(3000, () => {
  console.log('Serverdor escuchando en http://localhost:3000');
});